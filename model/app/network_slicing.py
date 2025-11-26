# ==============================================================
# network_slicing.py — 5G/6G Network Slice Manager for DDoS System
# ==============================================================

from datetime import datetime

# ==============================================================
# 5G/6G SLICE DEFINITIONS
# ==============================================================

SLICE_DEFINITIONS = {
    "eMBB": {
        "description": "Enhanced Mobile Broadband",
        "priority": 2,         # medium priority
        "bandwidth_weight": 0.50,  # 50% allotted band
        "ideal_use": "High-speed data, streaming, big packets"
    },
    "URLLC": {
        "description": "Ultra Reliable Low Latency Communications",
        "priority": 1,         # highest priority
        "bandwidth_weight": 0.30,
        "ideal_use": "Critical real-time traffic, low latency"
    },
    "mMTC": {
        "description": "Massive Machine Type Communications",
        "priority": 3,         # lowest priority
        "bandwidth_weight": 0.20,
        "ideal_use": "IoT sensors, small frequent packets"
    }
}

# ==============================================================
# SELECT SLICE BASED ON PACKET FEATURES
# ==============================================================

def classify_slice(packet_size: int, protocol: str, pps: float) -> str:
    """
    Determines most appropriate network slice:
    
    - eMBB  → large packets, video, TCP/UDP heavy data
    - URLLC → low latency + high PPS (critical small packets)
    - mMTC  → very small packets or large number of device-like traffic
    """

    # ---- URLLC detection (low latency traffic) ----
    if pps > 200 or protocol == "ICMP":
        return "URLLC"

    # ---- mMTC detection (IoT style traffic) ----
    if packet_size < 200 and pps < 20:
        return "mMTC"

    # ---- eMBB detection (high data) ----
    return "eMBB"


# ==============================================================
# SLICE POLICY RESPONSE
# ==============================================================

def apply_slice_policy(slice_name: str) -> dict:
    """
    Returns QoS policy parameters for controllers, logs, frontend etc.
    """

    slice_info = SLICE_DEFINITIONS.get(slice_name, SLICE_DEFINITIONS["eMBB"])

    return {
        "slice": slice_name,
        "priority": slice_info["priority"],
        "bandwidth_weight": slice_info["bandwidth_weight"],
        "description": slice_info["description"],
        "ideal_use": slice_info["ideal_use"],
        "timestamp": datetime.now().isoformat()
    }


# ==============================================================
# MAIN ENTRY FUNCTION (you will call this)
# ==============================================================

def get_network_slice(packet_size: int, protocol: str, pps: float) -> dict:
    """
    Computes:
        - slice type (eMBB / URLLC / mMTC)
        - slice policy
        - extra metadata to send to Node frontend

    RETURNS:
        {
            "slice": "eMBB",
            "priority": 2,
            "bandwidth_weight": 0.5,
            "description": "...",
            "ideal_use": "...",
            "timestamp": "...",
        }
    """

    slice_name = classify_slice(packet_size, protocol, pps)
    return apply_slice_policy(slice_name)
