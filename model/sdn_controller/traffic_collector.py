"""
Traffic Collector for DDoS Detection

This module collects and processes network traffic for DDoS detection.
It handles both real-time traffic collection and flow statistics.
"""
import os
import time
import socket
import struct
import threading
import queue
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any

from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('traffic_collector')

class TrafficCollector:
    """
    Collects and processes network traffic for DDoS detection.
    
    This class provides functionality to:
    - Capture raw network packets
    - Track flow statistics
    - Save collected data for analysis
    - Generate traffic samples for model training
    """
    
    def __init__(self, interface=None, output_file=None, max_samples=1000, sampling_interval=60):
        """
        Initialize the traffic collector.
        
        Args:
            interface: Network interface to monitor
            output_file: File to save collected traffic data
            max_samples: Maximum number of samples to keep in memory
            sampling_interval: Interval in seconds between flow samples
        """
        self.interface = interface or self._get_default_interface()
        self.output_file = output_file or f"traffic_{int(time.time())}.pcap"
        self.max_samples = max_samples
        self.sampling_interval = sampling_interval
        
        # Data structures
        self.packet_queue = queue.Queue()
        self.flow_stats = defaultdict(lambda: {
            'start_time': 0,
            'packet_count': 0,
            'byte_count': 0,
            'last_seen': 0,
            'protocol': None,
            'src_port': None,
            'dst_port': None
        })
        self.samples = deque(maxlen=max_samples)
        
        # State
        self.running = False
        self.threads = []
        self.packet_count = 0
        self.last_sample_time = time.time()
        
    def _get_default_interface(self):
        """Get the default network interface."""
        import netifaces
        return netifaces.gateways()['default'][netifaces.AF_INET][1]
    
    def _parse_packet(self, packet: bytes) -> Optional[Dict]:
        """
        Parse a raw network packet and extract flow information.
        
        Args:
            packet: Raw packet data
            
        Returns:
            Dictionary containing flow information or None if invalid
        """
        try:
            # Parse packet using scapy
            pkt = IP(packet)
            
            # Extract basic packet information
            packet_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'length': len(packet),
                'protocol': None,
                'src_ip': pkt.src,
                'dst_ip': pkt.dst,
                'dst_port': None,
                'flags': None
            }
            
            # Process transport layer
            if pkt.haslayer(TCP):
                packet_info['protocol'] = 'tcp'
                packet_info['src_port'] = pkt[TCP].sport
                packet_info['dst_port'] = pkt[TCP].dport
                packet_info['flags'] = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                packet_info['protocol'] = 'udp'
                packet_info['src_port'] = pkt[UDP].sport
                packet_info['dst_port'] = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                packet_info['protocol'] = 'icmp'
                
            return packet_info
            
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
    
    def _packet_handler(self, packet):
        """Process each captured packet."""
        if not self.running:
            return
            
        try:
            self.packet_count += 1
            
            # Parse the packet
            packet_info = self._parse_packet(bytes(packet))
            if not packet_info:
                return
                
            # Add to queue for processing
            self.packet_queue.put(packet_info)
            self._update_flow_stats(packet_info)
            
            # Sample flows at regular intervals
            current_time = time.time()
            if current_time - self.last_sample_time >= self.sampling_interval:
                self._sample_flows()
                self.last_sample_time = current_time
                
        except Exception as e:
            logger.error(f"Error in packet handler: {e}")
    
    def _update_flow_stats(self, packet_info: Dict) -> None:
        """
        Update flow statistics with information from a packet.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        required_keys = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        if not all(k in packet_info for k in required_keys):
            return
            
        # Create a flow key
        flow_key = (
            packet_info['src_ip'], 
            packet_info['dst_ip'], 
            packet_info['src_port'], 
            packet_info['dst_port'], 
            packet_info['protocol']
        )
        
        # Initialize flow stats if it's a new flow
        if self.flow_stats[flow_key]['start_time'] == 0:
            self.flow_stats[flow_key].update({
                'start_time': time.time(),
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'src_port': packet_info['src_port'],
                'dst_port': packet_info['dst_port'],
                'protocol': packet_info['protocol']
            })
        
        # Update flow statistics
        self.flow_stats[flow_key].update({
            'packet_count': self.flow_stats[flow_key]['packet_count'] + 1,
            'byte_count': self.flow_stats[flow_key].get('byte_count', 0) + packet_info['length'],
            'last_seen': time.time()
        })
    
    def _sample_flows(self) -> None:
        """Sample active flows and add to samples."""
        current_time = time.time()
        
        for flow_key, stats in list(self.flow_stats.items()):
            # Skip flows that haven't been updated since last sample
            if current_time - stats['last_seen'] > self.sampling_interval * 2:
                continue
                
            # Calculate flow duration
            duration = stats['last_seen'] - stats['start_time']
            
            # Calculate packets/bytes per second
            if duration > 0:
                pps = stats['packet_count'] / duration
                bps = stats['byte_count'] / duration
            else:
                pps = bps = 0
            
            # Create a flow sample
            sample = {
                'timestamp': datetime.utcnow().isoformat(),
                'src_ip': stats['src_ip'],
                'dst_ip': stats['dst_ip'],
                'src_port': stats['src_port'],
                'dst_port': stats['dst_port'],
                'protocol': stats['protocol'],
                'duration': duration,
                'packet_count': stats['packet_count'],
                'byte_count': stats['byte_count'],
                'packets_per_sec': pps,
                'bytes_per_sec': bps
            }
            
            self.samples.append(sample)
            
        logger.info(f"Sampled {len(self.samples)} flows")
    
    def _process_queue(self):
        """Process packets from the queue."""
        while self.running or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                # Here you can add custom processing logic
                # For example, feature extraction or attack detection
                self.packet_queue.task_done()
            except queue.Empty:
                continue
    
    def start(self, timeout: Optional[float] = None) -> None:
        """
        Start the traffic collection.
        
        Args:
            timeout: Maximum time in seconds to run the collection (None for unlimited)
        """
        if self.running:
            logger.warning("Traffic collection is already running")
            return
            
        self.running = True
        self.packet_count = 0
        self.flow_stats.clear()
        self.samples.clear()
        
        # Start packet processing thread
        processor = threading.Thread(target=self._process_queue)
        processor.daemon = True
        processor.start()
        self.threads.append(processor)
        
        # Start sniffing
        logger.info(f"Starting traffic collection on interface {self.interface}")
        logger.info(f"Saving output to {self.output_file}")
        
        # Use scapy's sniff function in a separate thread
        sniffer = threading.Thread(
            target=sniff,
            kwargs={
                'iface': self.interface,
                'prn': self._packet_handler,
                'store': 0,
                'timeout': timeout
            }
        )
        sniffer.daemon = True
        sniffer.start()
        self.threads.append(sniffer)
        
        # Start a thread to periodically save samples
        if self.output_file:
            saver = threading.Thread(
                target=self._periodic_save,
                args=(self.output_file, 300)  # Save every 5 minutes
            )
            saver.daemon = True
            saver.start()
            self.threads.append(saver)
        
        return self
    
    def stop(self) -> None:
        """Stop the traffic collection and cleanup resources."""
        if not self.running:
            return
            
        logger.info("Stopping traffic collection...")
        self.running = False
        
        # Wait for threads to complete
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        # Save any remaining data
        if self.output_file:
            self._save_samples(self.output_file)
            
        logger.info(f"Collection stopped. Processed {self.packet_count} packets")
        logger.info(f"Detected {len(self.flow_stats)} unique flows")
    
    def _periodic_save(self, filename: str, interval: int) -> None:
        """
        Periodically save collected samples to a file.
        
        Args:
            filename: Output filename
            interval: Save interval in seconds
        """
        while self.running:
            time.sleep(interval)
            if self.samples:
                self._save_samples(filename)
    
    def _save_samples(self, filename: str) -> None:
        """
        Save collected samples to a file.
        
        Args:
            filename: Output filename
        """
        if not self.samples:
            return
            
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            
            # Save samples to file
            with open(filename, 'a') as f:
                for sample in self.samples:
                    f.write(json.dumps(sample) + '\n')
            
            logger.info(f"Saved {len(self.samples)} samples to {filename}")
            self.samples.clear()
            
        except Exception as e:
            logger.error(f"Failed to save samples: {e}")
    
    def _save_flow_stats(self) -> None:
        """Save flow statistics to a JSON file."""
        if not self.flow_stats:
            return
            
        stats_file = self.output_file.replace('.pcap', '_flows.json')
        
        try:
            # Convert flow stats to a list of dictionaries
            flows = []
            for flow_key, stats in self.flow_stats.items():
                if stats['packet_count'] == 0:  # Skip empty flows
                    continue
                    
                flow = {
                    'flow_id': f"{stats['src_ip']}:{stats['src_port']}-{stats['dst_ip']}:{stats['dst_port']}-{stats['protocol']}",
                    'start_time': datetime.fromtimestamp(stats['start_time']).isoformat(),
                    'end_time': datetime.fromtimestamp(stats['last_seen']).isoformat(),
                    'duration': stats['last_seen'] - stats['start_time'],
                    'packet_count': stats['packet_count'],
                    'byte_count': stats['byte_count'],
                    'source': {
                        'ip': stats['src_ip'],
                        'port': stats['src_port']
                    },
                    'destination': {
                        'ip': stats['dst_ip'],
                        'port': stats['dst_port']
                    },
                    'protocol': stats['protocol']
                }
                flows.append(flow)
            
            # Save to file
            with open(stats_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.utcnow().isoformat(),
                    'total_flows': len(flows),
                    'total_packets': self.packet_count,
                    'flows': flows
                }, f, indent=2)
                
            logger.info(f"Saved flow statistics to {stats_file}")
            
        except Exception as e:
            logger.error(f"Failed to save flow statistics: {e}")
    
    def get_samples(self, limit: int = 100) -> List[Dict]:
        """
        Get collected samples.
        
        Args:
            limit: Maximum number of samples to return
            
        Returns:
            List of sample dictionaries
        """
        return list(self.samples)[-limit:]
    
    def get_flow_stats(self) -> Dict:
        """
        Get current flow statistics.
        
        Returns:
            Dictionary containing flow statistics
        """
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'packet_count': self.packet_count,
            'active_flows': len(self.flow_stats),
            'samples_collected': len(self.samples)
        }
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()

def collect_traffic(interface=None, duration=60, output_file=None):
    """
    Collect traffic for the specified duration.
    
    Args:
        interface: Network interface to monitor
        duration: Duration in seconds to collect traffic
        output_file: Output file path
    """
    with TrafficCollector(interface=interface, output_file=output_file) as collector:
        try:
            print(f"Collecting traffic for {duration} seconds (press Ctrl+C to stop)...")
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\nTraffic collection stopped by user")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Traffic Collector')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-d', '--duration', type=int, default=60, 
                       help='Duration to collect traffic (seconds)')
    parser.add_argument('-o', '--output', help='Output file path')
    
    args = parser.parse_args()
    
    collect_traffic(
        interface=args.interface,
        duration=args.duration,
        output_file=args.output
    )
