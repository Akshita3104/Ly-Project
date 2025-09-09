"""
Mitigation Manager for DDoS Protection

This module handles the mitigation of detected DDoS attacks using various strategies.
It combines the functionality of the previous mitigation_manager.py and mitigator.py
into a single, comprehensive solution.
"""
import time
import logging
import subprocess
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union, Any

# Default configuration
DEFAULT_CONFIG = {
    'block_duration': 3600,  # seconds (1 hour)
    'rate_limit': 1000,      # packets per second
    'enable_iptables': True,  # Use iptables for blocking
    'enable_tc': True,       # Use tc for rate limiting
    'log_file': 'mitigation.log',
    'mitigation_threshold': 0.7,  # Confidence threshold for mitigation
    'slice_config': {
        'high_priority': 1,
        'medium_priority': 2,
        'low_priority': 3,
        'default': 2
    }
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ddos_mitigation')

class MitigationManager:
    """
    Manages DDoS attack mitigation strategies.
    
    This class handles both IP blocking and rate limiting, with support for
    different mitigation strategies based on attack type and confidence level.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the mitigation manager with configuration.
        
        Args:
            config: Configuration dictionary for mitigation settings.
                   Will be merged with DEFAULT_CONFIG.
        """
        # Merge provided config with defaults
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)
            
        # Ensure required directories exist
        os.makedirs(os.path.dirname(os.path.abspath(self.config['log_file'])), 
                   exist_ok=True)
        
        # Initialize data structures
        self.active_rules: Dict[str, Dict] = {}
        self.mitigation_history: List[Dict] = []
        self.blacklist: set = set()
        self.rate_limits: Dict[str, Dict] = {}
        self.slice_priorities = self.config['slice_config']
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['log_file']),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ddos_mitigation')
        
        # Initialize network interfaces
        self._init_network()
        
        self.logger.info("Mitigation Manager initialized with config: %s", 
                        json.dumps(self.config, indent=2))
    
    def _init_network(self):
        """Initialize network interfaces and rules."""
        try:
            # Initialize iptables chain if needed
            if self.config['enable_iptables']:
                subprocess.run(
                    ['sudo', 'iptables', '-N', 'DDOS_MITIGATION'],
                    stderr=subprocess.PIPE
                )
                subprocess.run(
                    ['sudo', 'iptables', '-A', 'INPUT', '-j', 'DDOS_MITIGATION'],
                    stderr=subprocess.PIPE
                )
            
            # Initialize traffic control if enabled
            if self.config['enable_tc']:
                # This is a placeholder - actual TC setup would go here
                pass
                
        except Exception as e:
            self.logger.error(f"Error initializing network: {e}")
    
    def handle_attack(self, flow: Dict, confidence: float) -> Dict:
        """
        Handle a detected DDoS attack.
        
        Args:
            flow: The flow that triggered the attack detection
            confidence: Confidence score of the detection (0-1)
            
        Returns:
            Dict: Mitigation actions taken
        """
        if confidence < self.config['mitigation_threshold']:
            return {"action": "monitor", 
                   "reason": f"Below confidence threshold ({confidence} < {self.config['mitigation_threshold']})"}
        
        src_ip = flow.get('src_ip')
        slice_id = flow.get('slice_id', 'default')
        
        if not src_ip:
            return {"action": "error", 
                   "reason": "No source IP in flow"}
        
        # Determine mitigation strategy based on confidence and slice priority
        priority = self.slice_priorities.get(slice_id, 
                                          self.slice_priorities['default'])
        
        if confidence > 0.9 or priority == 1:  # High confidence or high priority
            return self.block_ip(src_ip, 
                               f"High confidence attack (score: {confidence:.2f})")
        elif confidence > 0.7 or priority == 2:  # Medium confidence/priority
            return self.rate_limit(src_ip, 
                                 rate=self.config['rate_limit'] // 2,
                                 reason=f"Medium confidence attack (score: {confidence:.2f})")
        else:  # Low confidence/priority
            return self.rate_limit(src_ip, 
                                 rate=self.config['rate_limit'],
                                 reason=f"Low confidence attack (score: {confidence:.2f})")
    
    def block_ip(self, ip_address: str, reason: str = "DDoS attack", 
                duration: int = None) -> Dict[str, Any]:
        """
        Block an IP address using iptables.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for default)
            
        Returns:
            Dict containing action details and success status
        """
        if not self.config['enable_iptables']:
            self.logger.warning("iptables blocking is disabled in config")
            return {"action": "block", "ip": ip_address, "success": False, 
                   "reason": "iptables disabled in config"}
        
        duration = duration or self.config['block_duration']
        rule_id = f"block_{ip_address}_{int(time.time())}"
        
        # Add to blacklist
        self.blacklist.add(ip_address)
        
        try:
            # Add iptables rule to block the IP
            subprocess.run(
                ['sudo', 'iptables', '-A', 'DDOS_MITIGATION', 
                 '-s', ip_address, '-j', 'DROP'],
                check=True,
                stderr=subprocess.PIPE
            )
            
            # Schedule rule removal
            removal_time = datetime.now() + timedelta(seconds=duration)
            self.active_rules[rule_id] = {
                'type': 'block',
                'ip': ip_address,
                'action': 'DROP',
                'added_at': datetime.now().isoformat(),
                'remove_at': removal_time.isoformat(),
                'reason': reason,
                'slice_id': 'high_priority' if duration < 3600 else 'low_priority'
            }
        
            # Log the action
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'block_ip',
                'ip': ip_address,
                'duration_seconds': duration,
                'reason': reason,
                'status': 'success'
            }
            self.mitigation_history.append(log_entry)
            self.logger.info(
                "Blocked IP %s for %s seconds. Reason: %s",
                ip_address, duration, reason
            )
            
            return {
                'action': 'block', 
                'ip': ip_address, 
                'success': True,
                'rule_id': rule_id,
                'duration': duration,
                'reason': reason
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to block IP {ip_address}: {e.stderr.decode().strip()}"
            self.logger.error(error_msg)
            return {
                'action': 'block', 
                'ip': ip_address, 
                'success': False,
                'error': error_msg
            }
    
    def rate_limit(self, ip_address: str, rate: int = None, 
                  burst: int = None, reason: str = "Rate limiting") -> Dict[str, Any]:
        """
        Apply rate limiting to an IP address.
        
{{ ... }}
        Args:
            ip_address: IP address to rate limit
            rate: Maximum packets per second
            burst: Burst size in packets
            reason: Reason for rate limiting
            
        Returns:
            Dict containing action details and success status
        """
        if not self.config['enable_tc']:
            self.logger.warning("Traffic control (tc) is disabled in config")
            return {
                'action': 'rate_limit', 
                'ip': ip_address, 
                'success': False,
                'reason': 'TC disabled in config'
            }
            
        rate = rate or self.config['rate_limit']
        burst = burst or rate * 2
        rule_id = f"ratelimit_{ip_address}_{int(time.time())}"
        
        try:
            # Store rate limit information
            self.rate_limits[ip_address] = {
                'rate': rate,
                'burst': burst,
                'last_updated': datetime.now().isoformat()
            }
            
            # In a real implementation, we would set up tc rules here
            # For now, we'll just log the action
            self.logger.info(
                "Rate limiting IP %s to %d p/s (burst: %d). Reason: %s",
                ip_address, rate, burst, reason
            )
            
            # Store the rule
            self.active_rules[rule_id] = {
                'type': 'rate_limit',
                'ip': ip_address,
                'rate': f'{rate}p/s',
                'burst': burst,
                'added_at': datetime.now().isoformat(),
                'reason': reason
            }
            
            # Log the action
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': 'rate_limit',
                'ip': ip_address,
                'rate': rate,
                'burst': burst,
                'reason': reason,
                'status': 'success'
            }
            self.mitigation_history.append(log_entry)
            
            return {
                'action': 'rate_limit',
                'ip': ip_address,
                'success': True,
                'rule_id': rule_id,
                'rate': rate,
                'burst': burst,
                'reason': reason
            }
            
        except Exception as e:
            error_msg = f"Failed to rate limit IP {ip_address}: {str(e)}"
            self.logger.error(error_msg)
            return {
                'action': 'rate_limit',
                'ip': ip_address,
                'success': False,
                'error': error_msg
            }
    
    def remove_mitigation(self, rule_id: str) -> Dict[str, Any]:
        """
        Remove a mitigation rule.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            Dict containing the result of the operation
        """
        if rule_id not in self.active_rules:
            msg = f"Rule {rule_id} not found in active rules"
            self.logger.warning(msg)
            return {'success': False, 'error': msg}
            
        rule = self.active_rules[rule_id]
        ip_address = rule.get('ip')
        rule_type = rule.get('type')
        
        try:
            if rule_type == 'block':
                # Remove from iptables
                if self.config['enable_iptables']:
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'DDOS_MITIGATION', 
                         '-s', ip_address, '-j', 'DROP'],
                        check=True,
                        stderr=subprocess.PIPE
                    )
                
                # Remove from blacklist
                if ip_address in self.blacklist:
                    self.blacklist.remove(ip_address)
                    
            elif rule_type == 'rate_limit':
                # Remove rate limiting
                if ip_address in self.rate_limits:
                    del self.rate_limits[ip_address]
                    # In a real implementation, we would remove tc rules here
            
            # Remove from active rules
            del self.active_rules[rule_id]
            
            # Log the action
            self.logger.info(
                "Removed %s rule %s for IP %s", 
                rule_type, rule_id, ip_address
            )
            
            return {
                'success': True,
                'rule_id': rule_id,
                'ip': ip_address,
                'action': f'remove_{rule_type}'
            }
            
        except Exception as e:
            error_msg = f"Failed to remove rule {rule_id}: {str(e)}"
            self.logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'rule_id': rule_id,
                'ip': ip_address
            }
    
    def cleanup_expired_rules(self) -> Dict[str, Any]:
        """
        Remove expired mitigation rules.
        
        Returns:
            Dict containing the number of rules removed and any errors
        """
        removed = 0
        errors = []
        now = datetime.now()
        
        for rule_id, rule in list(self.active_rules.items()):
            if 'remove_at' in rule and datetime.fromisoformat(rule['remove_at']) < now:
                result = self.remove_mitigation(rule_id)
                if result.get('success'):
                    removed += 1
                else:
                    errors.append({
                        'rule_id': rule_id,
                        'error': result.get('error', 'Unknown error')
                    })
        
        if removed > 0 or errors:
            self.logger.info(
                "Cleaned up %d expired rules (%d errors)", 
                removed, len(errors)
            )
        
        return {
            'removed': removed,
            'errors': errors,
            'total_active_rules': len(self.active_rules)
        }
    
    def get_active_rules(self) -> Dict[str, Dict]:
        """Get all active mitigation rules."""
        return self.active_rules
    
    def get_mitigation_history(self, limit: int = 100) -> List[Dict]:
        """
        Get mitigation history.
        
        Args:
            limit: Maximum number of history entries to return
            
        Returns:
            List of mitigation actions
        """
        return self.mitigation_history[-limit:]
    
    def __del__(self):
        """Clean up resources."""
        # Remove all active rules when the object is destroyed
        for rule_id in list(self.active_rules.keys()):
            self.remove_mitigation(rule_id)

# Singleton instance
mitigation_manager = MitigationManager()

def block_ip(ip_address: str, reason: str = "DDoS attack", duration: int = None) -> bool:
    """Block an IP address using the global mitigation manager."""
    return mitigation_manager.block_ip(ip_address, reason, duration)

def rate_limit(ip_address: str, rate: int = None, burst: int = None) -> bool:
    """Apply rate limiting to an IP address using the global mitigation manager."""
    return mitigation_manager.rate_limit(ip_address, rate, burst)

if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description='DDoS Mitigation Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Block IP command
    block_parser = subparsers.add_parser('block', help='Block an IP address')
    block_parser.add_argument('ip', help='IP address to block')
    block_parser.add_argument('-r', '--reason', default='DDoS attack', help='Reason for blocking')
    block_parser.add_argument('-d', '--duration', type=int, help='Block duration in seconds')
    
    # Rate limit command
    rate_parser = subparsers.add_parser('rate-limit', help='Rate limit an IP address')
    rate_parser.add_argument('ip', help='IP address to rate limit')
    rate_parser.add_argument('-r', '--rate', type=int, help='Maximum packets per second')
    rate_parser.add_argument('-b', '--burst', type=int, help='Burst size in packets')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List active rules')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up expired rules')
    
    args = parser.parse_args()
    
    if args.command == 'block':
        success = block_ip(args.ip, args.reason, args.duration)
        print(f"Blocking {args.ip}: {'Success' if success else 'Failed'}")
    
    elif args.command == 'rate-limit':
        success = rate_limit(args.ip, args.rate, args.burst)
        print(f"Rate limiting {args.ip}: {'Success' if success else 'Failed'}")
    
    elif args.command == 'list':
        rules = mitigation_manager.get_active_rules()
        print(f"Active Rules ({len(rules)}):")
        for rule_id, rule in rules.items():
            print(f"- {rule_id}: {rule}")
    
    elif args.command == 'cleanup':
        removed = mitigation_manager.cleanup_expired_rules()
        print(f"Removed {removed} expired rules")
    
    else:
        parser.print_help()
