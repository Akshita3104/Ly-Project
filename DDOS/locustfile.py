# locustfile.py  (safe simulated DDoS with X-Forwarded-For random IPs + Sentinel /simulate-packet)
from locust import HttpUser, task, between
import random
import string
import uuid
import time

# TARGET_BACKEND should point to your Node backend (website / API)
TARGET_BACKEND = "http://127.0.0.1:3000"  # or "http://192.168.0.100:3000"

# SENTINEL_BACKEND should point to your Flask/Scapy ML app (app.py)
SENTINEL_BACKEND = "http://127.0.0.1:5001"  # change if Sentinel runs elsewhere

def rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def rand_ip():
    # generate nice demo IPv4 addresses (avoid reserved ranges)
    return "{}.{}.{}.{}".format(
        random.randint(11, 223),
        random.randint(1, 254),
        random.randint(1, 254),
        random.randint(1, 254),
    )

class Attacker(HttpUser):
    # This host is used for your main Node backend (site / API load).
    host = TARGET_BACKEND
    wait_time = between(0.01, 0.12)   # aggressive for demo

    @property
    def attack_headers(self):
        # Headers used when hitting the Node backend.
        return {
            "User-Agent": f"LocustAttacker/{uuid.uuid4().hex[:6]}",
            "X-Simulated-Attack": "true",   # <--- lets Node know this is simulated
            "X-Forwarded-For": rand_ip(),   # <--- fake client IP for logs/analysis
        }

    @task(7)
    def many_gets(self):
        """
        Simulate many GET requests to your Node backend (web/API paths).
        """
        path = random.choice(
            ["/", "/login", "/api/v1/resource", "/heavy", "/static/img.png", "/api/health"]
        )
        self.client.get(
            path,
            headers=self.attack_headers,
            name="GET " + path,
            timeout=10,
        )

    @task(3)
    def many_posts(self):
        """
        Simulate many POST requests to your Node backend.
        """
        payload = {"name": rand_str(6), "value": random.randint(1, 100)}
        path = random.choice(["/api/v1/submit", "/api/v1/update", "/api/v1/upload"])
        self.client.post(
            path,
            json=payload,
            headers=self.attack_headers,
            name="POST " + path,
            timeout=10,
        )

    @task(10)
    def simulated_ddos_to_sentinel(self):
        """
        Send high-rate synthetic packets to Sentinel's /simulate-packet endpoint.
        These packets are marked as simulated, so Sentinel will ALWAYS classify
        them as malicious and report them to the Node backend.
        """
        src_ip = rand_ip()
        now_ms = int(time.time() * 1000)

        payload = {
            "srcIP": src_ip,            # visible in Sentinel + frontend tables
            "dstIP": "127.0.0.1",       # or the protected service IP
            "protocol": "TCP",
            "packetSize": random.randint(400, 900),
            "timestamp": now_ms,
            "simulated": True,          # body flag for Sentinel / Node pipelines
        }

        headers = {
            "User-Agent": f"LocustSentinel/{uuid.uuid4().hex[:6]}",
            "X-Simulated-Attack": "true",  # Sentinel reads this as simulated
            "X-Forwarded-For": src_ip,     # same as srcIP for consistency
        }

        # Use an absolute URL so this call goes to Sentinel, not Node.
        self.client.post(
            f"{SENTINEL_BACKEND}/simulate-packet",
            json=payload,
            headers=headers,
            name="SENTINEL /simulate-packet",
            timeout=10,
        )
