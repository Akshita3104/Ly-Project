from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import logging
import threading
import time
import socket
from datetime import datetime
from collections import defaultdict, deque

# ---------- Network Slicing ----------
from network_slicing import get_network_slice

# ---------- 3rd party ----------
from scapy.all import sniff, IP          # <-- FAST capture
import joblib
import numpy as np

# ==========================================================
app = Flask(__name__)
CORS(app, origins=["*"])

# === LOGGING ===
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("SENTINEL")

# === AUTO-DETECT LAPTOP IP ===
def get_laptop_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 1))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

LAPTOP_IP = get_laptop_ip()
log.info(f"LAPTOP IP AUTO DETECTED → {LAPTOP_IP}")

# ==========================================================
# CONFIGURATION
# ==========================================================
# NOTE: update this IP if your Mininet VM IP changes
RYU_URL        = "http://192.168.56.101:8080"

# Node backend lives on the same Windows laptop as this Flask app
NODE_HOST      = "localhost"
NODE_URL       = f"http://{NODE_HOST}:3000/api/emit-blocked-ip"
NODE_LIVEPACKET= f"http://{NODE_HOST}:3000/api/live-packet"

MODEL_PATH = "../models/randomforest_enhanced.pkl"
BLOCKED_IPS    = set()
running        = False

# === SIMULATED ATTACK / LOCUST SUPPORT ====================
# Any IPs added here will ALWAYS be treated as malicious.
FORCE_MALICIOUS_IPS = set()

# === PROTOCOL NUMBER → NAME MAPPING ===
PROTOCOL_MAP = {
    1:  "ICMP",
    2:  "IGMP",
    6:  "TCP",
    17: "UDP",
    89: "OSPF",
    41: "IPv6",
    50: "ESP",
    51: "AH",
    # Add more as needed
}

# === LOAD ML MODEL + PRINT EXPECTED FEATURES ===
model = None
try:
    model = joblib.load(MODEL_PATH)
    log.info("ML MODEL LOADED → AI DETECTION ACTIVE")
    log.info(f"   → Model expects {model.n_features_in_} features")
    if hasattr(model, "feature_names_in_"):
        log.info(f"   → Feature names: {list(model.feature_names_in_)}")
except Exception as e:
    log.warning(f"NO ML MODEL FOUND → fallback rule ({e})")

# ==========================================================
# RYU CONTROLLER: BLOCK / UNBLOCK
# ==========================================================
def block_ip(ip: str) -> bool:
    """
    Install a DROP flow in Ryu to block all IPv4 traffic from `ip`.
    """
    if ip in BLOCKED_IPS:
        return True

    url = f"{RYU_URL}/stats/flowentry/add"

    # IMPORTANT:
    # - dpid must be an INTEGER (our Mininet switch is ID 1)
    # - eth_type=0x0800 to match IPv4 packets
    rule = {
        "dpid": 1,
        "priority": 60000,
        "match": {
            "eth_type": 0x0800,
            "ipv4_src": ip
        },
        "actions": []  # empty actions => DROP
    }

    try:
        r = requests.post(url, json=rule, timeout=3)
        if r.ok:
            BLOCKED_IPS.add(ip)
            log.warning(f"BLOCKED {ip} → SDN DROP RULE ADDED")
            return True
        else:
            log.error(f"RYU flow add failed: {r.status_code} {r.text}")
    except Exception as e:
        log.error(f"RYU CONTROLLER UNREACHABLE: {e}")
    return False


def unblock_ip(ip: str) -> bool:
    """
    Remove the DROP flow for `ip` from Ryu.
    """
    if ip not in BLOCKED_IPS:
        return True

    url = f"{RYU_URL}/stats/flowentry/delete"

    rule = {
        "dpid": 1,
        "match": {
            "eth_type": 0x0800,
            "ipv4_src": ip
        }
    }

    try:
        r = requests.post(url, json=rule, timeout=3)
        if r.ok:
            BLOCKED_IPS.discard(ip)
            log.info(f"UNBLOCKED {ip} → SDN DROP RULE REMOVED")
            return True
        else:
            log.error(f"RYU flow delete failed: {r.status_code} {r.text}")
    except Exception as e:
        log.error(f"Failed to unblock {ip}: {e}")
    return False

# ==========================================================
# RATE TRACKER (per source IP) → real PPS for DDoS check
# ==========================================================
class RateTracker:
    def __init__(self, window=1.0):
        self.window = window
        self.timestamps = defaultdict(deque)

    def add(self, src_ip: str, ts: float):
        q = self.timestamps[src_ip]
        q.append(ts)
        while q and ts - q[0] > self.window:
            q.popleft()

    def pps(self, src_ip: str) -> float:
        q = self.timestamps[src_ip]
        return len(q) / self.window if q else 0.0

rate_tracker = RateTracker(window=1.0)

# ==========================================================
# ML / FALLBACK DETECTOR
# ==========================================================
EXPECTED_FEATURES = model.n_features_in_ if model else 0

def build_features(pkt_size: int, pps: float) -> list:
    base = [
        1,                # packet_count (dummy)
        pps,              # packets per second
        pkt_size / 100,   # avg packet size (scaled)
        0.5,              # protocol entropy (dummy)
        0.3,              # src-port entropy (dummy)
        10.0,             # flow duration (dummy)
        1,                # SYN flag (dummy)
        1,                # ACK flag (dummy)
        1                 # is_tcp (dummy)
    ]
    if len(base) > EXPECTED_FEATURES:
        return base[:EXPECTED_FEATURES]
    elif len(base) < EXPECTED_FEATURES:
        return base + [0.0] * (EXPECTED_FEATURES - len(base))
    return base

def is_ddos_attack(pkt_size: int, pps: float) -> bool:
    if model:
        try:
            feats = build_features(pkt_size, pps)
            pred = model.predict([feats])[0]
            prob = model.predict_proba([feats])[0].max()
            return pred == 1 and prob > 0.7
        except Exception as e:
            log.error(f"ML predict error: {e}")
            return False
    else:
        # Simple fallback: treat > 50 pps as DDoS
        return pps > 50

def is_ddos_attack_for_ip(src_ip: str, pkt_size: int, pps: float, simulated: bool = False) -> bool:
    """
    Wrapper that lets us mark Locust / simulated traffic as always malicious.
    """
    # Any simulated traffic is always treated as malicious
    if simulated:
        return True

    # Any IP in FORCE_MALICIOUS_IPS is always malicious
    if src_ip in FORCE_MALICIOUS_IPS:
        return True

    # Otherwise, defer to ML / fallback
    return is_ddos_attack(pkt_size, pps)

# ==========================================================
# LIVE-PACKET THROTTLE (max 10 POSTs / sec)
# ==========================================================
last_live_ts = 0.0
LIVE_POST_INTERVAL = 0.1

def throttled_live_post(payload: dict):
    global last_live_ts
    now = time.time()
    if now - last_live_ts >= LIVE_POST_INTERVAL:
        try:
            requests.post(NODE_LIVEPACKET, json=payload, timeout=0.1)
            last_live_ts = now
        except Exception:
            pass

# ==========================================================
# SCAPY CAPTURE LOOP (REAL TRAFFIC)
# ==========================================================
def capture_loop():
    global running
    log.info(f"STARTING FAST SCAPY CAPTURE on Wi-Fi → dst host {LAPTOP_IP}")

    def packet_handler(pkt):
        if not running:
            return
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip   = ip_layer.src
        dst_ip   = ip_layer.dst
        size     = len(pkt)
        proto    = ip_layer.proto

        now = time.time()
        rate_tracker.add(src_ip, now)
        pps = rate_tracker.pps(src_ip)

        # ---------- PROTOCOL NAME ----------
        protocol_name = PROTOCOL_MAP.get(proto, f"Proto {proto}")

        # ---------- NETWORK SLICING (REAL TRAFFIC) ----------
        try:
            slice_info = get_network_slice(size, protocol_name, pps)
            network_slice = slice_info["slice"]
            slice_priority = slice_info["priority"]
        except Exception as e:
            log.error(f"network slicing error: {e}")
            network_slice = "eMBB"
            slice_priority = 2

        # ---------- LIVE PACKET (throttled) ----------
        throttled_live_post({
            "srcIP": src_ip,
            "dstIP": dst_ip,
            "protocol": protocol_name,        # "UDP", "TCP", etc.
            "packetSize": size,
            "timestamp": int(now * 1000),
            "network_slice": network_slice,   # slice for frontend
            "slice_priority": slice_priority  # optional
            # real captured traffic → no detection flags here
        })

        # ---------- DDoS DETECTION ----------
        if is_ddos_attack_for_ip(src_ip, size, pps, simulated=False):
            if block_ip(src_ip):
                try:
                    # also send slice info to Node for "Blocked Attackers" table
                    requests.post(
                        NODE_URL,
                        json={
                            "ip": src_ip,
                            "reason": f"DDoS Flood ({pps:.0f} pps, {protocol_name}, slice={network_slice})",
                            "threatLevel": "high",
                            "timestamp": datetime.now().isoformat(),
                            "isSimulated": False,
                            "network_slice": network_slice,
                            "slice_priority": slice_priority,
                        },
                        timeout=1,
                    )
                except Exception:
                    pass

    try:
        sniff(
            iface="Wi-Fi",
            filter=f"dst host {LAPTOP_IP}",
            prn=packet_handler,
            store=False,
            stop_filter=lambda x: not running
        )
    except Exception as e:
        log.error(f"Scapy capture crashed: {e}")
    finally:
        running = False
        log.info("CAPTURE THREAD EXITED")

# ==========================================================
# API ROUTES
# ==========================================================

@app.post("/simulate-packet")
def simulate_packet():
    """
    Synthetic packet endpoint used by Locust / demo.

    For the project demo we treat EVERYTHING coming here as a
    simulated DDoS packet so that:
      - Ryu blocks the srcIP
      - Node shows it in the "Blocked Attackers" table
      - Node also shows it in the Live Packets table as MALICIOUS (red)
    """
    try:
        data = request.get_json(force=True) or {}

        # --- Treat all /simulate-packet traffic as simulated attack ---
        is_simulated = True

        # Prefer JSON srcIP, else X-Forwarded-For, else real client IP
        src_ip = (
            data.get("srcIP")
            or data.get("srcIp")
            or data.get("src")
            or request.headers.get("X-Forwarded-For")
            or request.remote_addr
            or "unknown"
        )

        dst_ip = (
            data.get("dstIP")
            or data.get("dstIp")
            or data.get("dst")
            or LAPTOP_IP
        )

        packet_size = int(data.get("packetSize") or data.get("size") or 0)
        ts = float(data.get("timestamp") / 1000.0) if data.get("timestamp") else time.time()
        proto = data.get("protocol", "UDP")

        # Update rate tracker (for PPS in reason string)
        rate_tracker.add(src_ip, ts)
        pps = rate_tracker.pps(src_ip)

        # ---------- NETWORK SLICING (SIMULATED TRAFFIC) ----------
        try:
            slice_info = get_network_slice(packet_size, proto, pps)
            network_slice = slice_info["slice"]
            slice_priority = slice_info["priority"]
        except Exception as e:
            log.error(f"network slicing (simulate) error: {e}")
            network_slice = "eMBB"
            slice_priority = 2

        # ---- SEND LIVE PACKET → Node (for LivePacketTable) ----
        live_payload = {
            "srcIP": src_ip,
            "dstIP": dst_ip,
            "protocol": proto,
            "packetSize": packet_size,
            "timestamp": int(ts * 1000),
            "isMalicious": True,
            "confidence": 0.99,
            "packet_data": {"simulated": True},
            "network_slice": network_slice,
            "slice_priority": slice_priority,
        }
        throttled_live_post(live_payload)

        # ---- DDoS DETECTION (forced malicious for simulated) ----
        # This will always return True because simulated=True
        is_ddos = is_ddos_attack_for_ip(src_ip, packet_size, pps, simulated=is_simulated)

        blocked = False
        if is_ddos:
            # block via Ryu
            blocked = block_ip(src_ip)
            if blocked:
                try:
                    requests.post(
                        NODE_URL,
                        json={
                            "ip": src_ip,
                            "reason": f"Simulated DDoS Attack (demo) ({pps:.0f} pps, slice={network_slice})",
                            "threatLevel": "simulated",
                            "timestamp": datetime.now().isoformat(),
                            "isSimulated": True,
                            "network_slice": network_slice,
                            "slice_priority": slice_priority,
                        },
                        timeout=1,
                    )
                except Exception:
                    pass

        log.warning(
            f"[SIMULATE] FORCED DDOS for {src_ip} (pps={pps:.1f}, simulated={is_simulated}, blocked={blocked}, slice={network_slice})"
        )
        return jsonify(
            {
                "pred": "ddos" if is_ddos else "normal",
                "pps": pps,
                "blocked": blocked,
                "simulated": is_simulated,
                "network_slice": network_slice,
                "slice_priority": slice_priority,
            }
        )

    except Exception as e:
        log.error(f"simulate-packet error: {e}")
        return jsonify({"error": str(e)}), 500


@app.post("/start-capture")
def start_capture():
    global running
    if running:
        return jsonify({"status": "already_running"})
    running = True    # start flag
    threading.Thread(target=capture_loop, daemon=True).start()
    log.info("PACKET CAPTURE STARTED")
    return jsonify({"status": "capturing", "ip": LAPTOP_IP})


@app.post("/stop-capture")
def stop_capture():
    global running
    running = False
    log.info("CAPTURE STOPPED")
    return jsonify({"status": "stopped"})


@app.get("/health")
def health():
    try:
        ryu_ok = requests.get(f"{RYU_URL}/stats/switches", timeout=2).ok
    except Exception:
        ryu_ok = False
    return jsonify({
        "status": "LIVE",
        "laptop_ip": LAPTOP_IP,
        "ryu_reachable": ryu_ok,
        "blocked_ips": len(BLOCKED_IPS),
        "ai_active": model is not None,
        "capturing": running,
        "model_features": model.n_features_in_ if model else 0
    })


@app.post("/unblock")
def unblock():
    data = request.get_json(force=True) or {}
    ip = data.get("ip")
    success = False
    if ip:
        success = unblock_ip(ip)
    return jsonify({"success": success})

# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    log.info("SENTINEL AI LIVE SYSTEM STARTED")
    log.info(f"Laptop IP → {LAPTOP_IP}")
    log.info(f"Node Backend → {NODE_URL}")
    log.info(f"Ryu Controller → {RYU_URL}")
    log.info("POST http://localhost:5001/start-capture to begin.")
    app.run(host="0.0.0.0", port=5001, debug=False)
