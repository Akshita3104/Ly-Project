"""
SDN Controller for DDoS Detection and Mitigation

This module implements an SDN controller that integrates with the DDoS detection system.
It uses the Ryu framework for OpenFlow communication.
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib import hub

import json
import time
import socket
import struct
from datetime import datetime

# Import our DDoS detection components
from ..flow_collector.collector import flow_collector
from ..feature_extractor.extractor import feature_extractor
from ..ml_models.ddos_detector import DDoSDetector
from ..mitigation.mitigation_manager import MitigationManager

class DDoSController(app_manager.RyuApp):
    """
    SDN Controller for DDoS detection and mitigation.
    """
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)
        
        # Initialize data structures
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats = {}
        self.port_stats = {}
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Initialize DDoS detector
        self.detector = DDoSDetector()
        
        # Initialize mitigation manager
        self.mitigation_manager = MitigationManager()
        
        # Load or train model (in a real implementation, load from file)
        # self.detector = DDoSDetector.load('path/to/model.pkl')
        
        # Start monitoring thread
        self.monitoring = True
        self.monitor_interval = 5  # seconds
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features reply and install default flow entries."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default rule: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Log switch connection
        self.logger.info(f"Switch connected: {datapath.id}")
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add a flow entry to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle packet_in messages from the switch."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore non-IP packets
        if eth.ethertype != 0x0800:
            return
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        # Extract flow information
        flow_info = {
            'timestamp': time.time(),
            'src_ip': ip_pkt.src,
            'dst_ip': ip_pkt.dst,
            'protocol': ip_pkt.proto,
            'packet_len': len(pkt),
            'in_port': in_port
        }
        
        # Extract transport layer info if available
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        if tcp_pkt:
            flow_info.update({
                'src_port': tcp_pkt.src_port,
                'dst_port': tcp_pkt.dst_port,
                'flags': tcp_pkt.bits
            })
        elif udp_pkt:
            flow_info.update({
                'src_port': udp_pkt.src_port,
                'dst_port': udp_pkt.dst_port
            })
        
        # Add flow to collector
        self._process_flow(flow_info)
        
        # Learn MAC address
        self.mac_to_port.setdefault(datapath.id, {})[eth.src] = in_port
        
        # If we know the destination MAC, install a flow rule
        if eth.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions)
        
        # Send the packet out
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)
    
    def _process_flow(self, flow_info):
        """Process flow information for DDoS detection."""
        try:
            # Add flow to collector
            flow_id = flow_collector.add_flow(flow_info)
            
            # Extract features
            features = feature_extractor.transform([flow_info])
            
            # Detect DDoS
            is_attack, confidence = self.detector.detect_ddos(features[0])
            
            if is_attack:
                self.logger.warning(
                    f"DDoS detected from {flow_info['src_ip']} to {flow_info['dst_ip']} "
                    f"(confidence: {confidence:.2f})"
                )
                
                # Apply mitigation
                mitigation = self.mitigation_manager.mitigate_attack(
                    src_ip=flow_info['src_ip'],
                    attack_type='ddos',
                    confidence=confidence,
                    details=flow_info
                )
                
                # Log the attack
                self._log_attack(flow_info, confidence, mitigation)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error processing flow: {e}")
            
        return False
    
    def _log_attack(self, flow_info, confidence, mitigation):
        """Log DDoS attack details."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': flow_info.get('src_ip'),
            'dst_ip': flow_info.get('dst_ip'),
            'protocol': flow_info.get('protocol'),
            'confidence': confidence,
            'mitigation': mitigation
        }
        
        # In a real implementation, you would save this to a log file or database
        self.logger.info(f"DDoS Attack Detected: {json.dumps(log_entry, indent=2)}")
    
    def _monitor(self):
        """Monitor network traffic and collect statistics."""
        while self.monitoring:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.monitor_interval)
    
    def _request_stats(self, datapath):
        """Request flow and port statistics from the switch."""
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Request flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        # Request port stats
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply from the switch."""
        body = ev.msg.body
        
        self.logger.info('datapath         '
                        'in-port  eth-dst           '
                        'out-port packets  bytes')
        self.logger.info('---------------- '
                        '-------- ----------------- '
                        '-------- -------- --------')
        
        for stat in sorted([flow for flow in body if flow.priority == 1],
                          key=lambda flow: (flow.match['in_port'],
                                          flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                           ev.msg.datapath.id,
                           stat.match['in_port'], stat.match['eth_dst'],
                           stat.instructions[0].actions[0].port,
                           stat.packet_count, stat.byte_count)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """Handle port statistics reply from the switch."""
        body = ev.msg.body
        
        self.logger.info('datapath         port     '
                        'rx-pkts  rx-bytes rx-error '
                        'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                        '-------- -------- -------- '
                        '-------- -------- --------')
        
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                           ev.msg.datapath.id, stat.port_no,
                           stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                           stat.tx_packets, stat.tx_bytes, stat.tx_errors)


def launch():
    """Launch the controller."""
    app_manager.require_app('ryu.app.ofctl.api')
    app_manager.require_app('ryu.app.ofctl.service')
    app_manager.require_app('ryu.app.wsgi')
    
    # Start the controller
    app_mgr = app_manager.AppManager.get_instance()
    app_mgr.instantiate(DDoSController, *[], **{})
    
    # Start the WSGI server for REST API
    from ryu.app.wsgi import WSGIApplication
    from ryu.app.wsgi import ControllerBase, route
    
    class DDOSRestApi(ControllerBase):
        def __init__(self, req, link, data, **config):
            super(DDOSRestApi, self).__init__(req, link, data, **config)
            self.ddos_controller = data['ddos_controller']
        
        @route('ddos', '/ddos/mitigations', methods=['GET'])
        def list_mitigations(self, req, **kwargs):
            return Response(
                content_type='application/json',
                body=json.dumps(self.ddos_controller.mitigation_manager.get_active_mitigations())
            )
        
        @route('ddos', '/ddos/mitigations/{ip}', methods=['DELETE'])
        def remove_mitigation(self, req, **kwargs):
            ip = kwargs['ip']
            success = self.ddos_controller.mitigation_manager.remove_mitigation(
                ip, 
                reason="manually_removed"
            )
            if success:
                return Response(status=200)
            return Response(status=404)
    
    # Register the WSGI application
    wsgi = WSGIApplication(instance=app_mgr)
    wsgi.register(DDOSRestApi, {'ddos_controller': app_mgr.applications[0]})
    
    # Start the main loop
    app_mgr.run()


if __name__ == '__main__':
    import sys
    from ryu.cmd import manager
    
    # Start the Ryu controller
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6653')
    sys.argv.append('ddos_controller')
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    
    manager.main()
