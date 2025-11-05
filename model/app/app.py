# ==========================================================
# model/app.py — SENTINEL AI (Scapy + Protocol Names)
# ==========================================================
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import logging
import threading
import time
import socket
from datetime import datetime
from collections import defaultdict, deque

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
RYU_URL        = "http://192.168.56.101:8080"
NODE_HOST      = "localhost"
NODE_URL       = f"http://{NODE_HOST}:3000/api/emit-blocked-ip"
NODE_LIVEPACKET= f"http://{NODE_HOST}:3000/api/live-packet"

MODEL_PATH     = "models/randomforest_dummy.pkl"
BLOCKED_IPS    = set()
running        = False

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
    if ip in BLOCKED_IPS:
        return True
    url = f"{RYU_URL}/stats/flowentry/add"
    rule = {
        "dpid": "0000000000000001",
        "priority": 60000,
        "match": {"ipv4_src": ip},
        "actions": []
    }
    try:
        r = requests.post(url, json=rule, timeout=3)
        if r.ok:
            BLOCKED_IPS.add(ip)
            log.warning(f"BLOCKED {ip} → SDN DROP RULE ADDED")
            return True
    except Exception as e:
        log.error(f"RYU CONTROLLER UNREACHABLE: {e}")
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
        return pps > 50

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
# SCAPY CAPTURE LOOP
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

        # ---------- LIVE PACKET (throttled) ----------
        throttled_live_post({
            "srcIP": src_ip,
            "dstIP": dst_ip,
            "protocol": protocol_name,        # ← NOW "UDP", "TCP", etc.
            "packetSize": size,
            "timestamp": int(now * 1000)
        })

        # ---------- DDoS DETECTION ----------
        if is_ddos_attack(size, pps):
            if block_ip(src_ip):
                try:
                    requests.post(NODE_URL, json={
                        "ip": src_ip,
                        "reason": f"DDoS Flood ({pps:.0f} pps, {protocol_name})",
                        "threatLevel": "high",
                        "timestamp": datetime.now().isoformat()
                    }, timeout=1)
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
@app.post("/start-capture")
def start_capture():
    global running
    if running:
        return jsonify({"status": "already_running"})
    running = True
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
    ip = request.json.get("ip")
    if ip and ip in BLOCKED_IPS:
        try:
            requests.post(f"{RYU_URL}/stats/flowentry/delete", json={
                "dpid": "0000000000000001",
                "match": {"ipv4_src": ip}
            }, timeout=3)
            BLOCKED_IPS.discard(ip)
            log.info(f"UNBLOCKED {ip}")
        except Exception as e:
            log.error(f"Failed to unblock {ip}: {e}")
    return jsonify({"success": True})

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