"""
Flow Collector Module

This module is responsible for collecting and preprocessing network flow data
from SDN switches before it's processed by the detection system.
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union

import numpy as np
import pandas as pd
from fastapi import HTTPException

from ..config.config import FEATURES, PROTOCOL_MAP, SLICE_CONFIG

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FlowCollector:
    """
    Collects and preprocesses network flow data from SDN switches.
    """
    
    def __init__(self):
        """Initialize the flow collector with empty flow data."""
        self.flow_data = []
        self.current_flow_id = 0
        
    def add_flow(self, flow: Dict) -> int:
        """
        Add a new flow to the collector.
        
        Args:
            flow: Dictionary containing flow data
                Expected keys: src_ip, dst_ip, src_port, dst_port, 
                             protocol, packet_count, byte_count, 
                             flow_duration, slice_id
                
        Returns:
            int: Assigned flow ID
        """
        try:
            # Validate required fields
            required_fields = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 
                             'protocol', 'packet_count', 'byte_count', 
                             'flow_duration', 'slice_id']
            
            if not all(field in flow for field in required_fields):
                missing = [f for f in required_fields if f not in flow]
                raise ValueError(f"Missing required fields: {missing}")
            
            # Generate flow ID and timestamp
            flow_id = self._generate_flow_id()
            timestamp = datetime.utcnow().isoformat()
            
            # Calculate derived metrics
            packets_per_second = flow['packet_count'] / max(flow['flow_duration'], 1)
            bytes_per_second = flow['byte_count'] / max(flow['flow_duration'], 1)
            
            # Standardize protocol
            protocol = self._standardize_protocol(flow['protocol'])
            
            # Create flow record
            flow_record = {
                'flow_id': flow_id,
                'timestamp': timestamp,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': int(flow['src_port']),
                'dst_port': int(flow['dst_port']),
                'protocol': protocol,
                'packet_count': int(flow['packet_count']),
                'byte_count': int(flow['byte_count']),
                'flow_duration': float(flow['flow_duration']),
                'packets_per_second': packets_per_second,
                'bytes_per_second': bytes_per_second,
                'slice_id': flow['slice_id'],
                'slice_priority': self._get_slice_priority(flow['slice_id'])
            }
            
            self.flow_data.append(flow_record)
            logger.info(f"Added flow {flow_id} to collector")
            return flow_id
            
        except Exception as e:
            logger.error(f"Error adding flow: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Invalid flow data: {str(e)}")
    
    def get_flow(self, flow_id: int) -> Optional[Dict]:
        """
        Retrieve a flow by its ID.
        
        Args:
            flow_id: The ID of the flow to retrieve
            
        Returns:
            Optional[Dict]: The flow data if found, None otherwise
        """
        for flow in self.flow_data:
            if flow['flow_id'] == flow_id:
                return flow
        return None
    
    def get_all_flows(self, limit: int = 1000) -> List[Dict]:
        """
        Retrieve all collected flows.
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            List[Dict]: List of flow records
        """
        return self.flow_data[-limit:]
    
    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert collected flows to a pandas DataFrame.
        
        Returns:
            pd.DataFrame: DataFrame containing flow data
        """
        return pd.DataFrame(self.flow_data)
    
    def _generate_flow_id(self) -> int:
        """Generate a unique flow ID."""
        self.current_flow_id += 1
        return self.current_flow_id
    
    @staticmethod
    def _standardize_protocol(protocol: Union[str, int]) -> int:
        """
        Convert protocol to a standardized numeric value.
        
        Args:
            protocol: Protocol name or number
            
        Returns:
            int: Standardized protocol number
        """
        if isinstance(protocol, int):
            return protocol
            
        protocol = str(protocol).lower()
        return PROTOCOL_MAP.get(protocol, PROTOCOL_MAP['other'])
    
    @staticmethod
    def _get_slice_priority(slice_id: str) -> int:
        """
        Get the priority level for a network slice.
        
        Args:
            slice_id: The ID of the network slice
            
        Returns:
            int: Priority level (higher = more important)
        """
        return SLICE_CONFIG.get(slice_id.lower(), SLICE_CONFIG['default'])


# Singleton instance
flow_collector = FlowCollector()
