"""
Feature Extractor Module

This module is responsible for transforming raw flow data into features
suitable for machine learning models.
"""
import logging
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

from ..config.config import FEATURES, PROTOCOL_MAP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FeatureExtractor:
    """
    Extracts and transforms features from network flow data for DDoS detection.
    """
    
    def __init__(self):
        """Initialize the feature extractor with necessary encoders and scalers."""
        self.scaler = StandardScaler()
        self.ip_encoder = LabelEncoder()
        self.slice_encoder = LabelEncoder()
        self.fitted = False
    
    def fit(self, flows: List[Dict]) -> 'FeatureExtractor':
        """
        Fit the feature extractor on the provided flow data.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            FeatureExtractor: The fitted feature extractor instance
        """
        if not flows:
            raise ValueError("No flow data provided for fitting")
        
        # Convert to DataFrame for easier manipulation
        df = pd.DataFrame(flows)
        
        # Fit encoders and scaler
        try:
            # Encode IP addresses and slice IDs
            all_ips = pd.concat([df['src_ip'], df['dst_ip']]).unique()
            self.ip_encoder.fit(np.append(all_ips, ['unknown']))
            
            if 'slice_id' in df.columns:
                self.slice_encoder.fit(df['slice_id'].unique())
            
            # Fit the scaler on numeric features
            numeric_cols = self._get_numeric_features(df)
            if not numeric_cols.empty:
                self.scaler.fit(numeric_cols)
            
            self.fitted = True
            logger.info("Feature extractor fitted successfully")
            
        except Exception as e:
            logger.error(f"Error fitting feature extractor: {str(e)}")
            raise
            
        return self
    
    def transform(self, flows: List[Dict]) -> np.ndarray:
        """
        Transform flow data into feature vectors.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            np.ndarray: Array of feature vectors
        """
        if not self.fitted:
            raise RuntimeError("Feature extractor has not been fitted")
        
        if not flows:
            return np.array([])
        
        try:
            df = pd.DataFrame(flows)
            
            # Encode categorical features
            df['src_ip_encoded'] = self._safe_encode(self.ip_encoder, df['src_ip'], 'unknown')
            df['dst_ip_encoded'] = self._safe_encode(self.ip_encoder, df['dst_ip'], 'unknown')
            
            if 'slice_id' in df.columns:
                df['slice_encoded'] = self._safe_encode(self.slice_encoder, df['slice_id'])
            
            # Get and scale numeric features
            numeric_df = self._get_numeric_features(df)
            if not numeric_df.empty:
                scaled_features = self.scaler.transform(numeric_df)
                numeric_df = pd.DataFrame(scaled_features, 
                                       columns=numeric_df.columns,
                                       index=numeric_df.index)
            
            # Combine all features
            feature_columns = [
                'src_ip_encoded', 'dst_ip_encoded', 'src_port', 'dst_port',
                'protocol', 'packet_count', 'byte_count', 'flow_duration',
                'packets_per_second', 'bytes_per_second'
            ]
            
            if 'slice_encoded' in df.columns:
                feature_columns.append('slice_encoded')
            
            # Select and return features as numpy array
            features = df[feature_columns].values
            return features
            
        except Exception as e:
            logger.error(f"Error transforming features: {str(e)}")
            raise
    
    def fit_transform(self, flows: List[Dict]) -> np.ndarray:
        """
        Fit the feature extractor and transform the data.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            np.ndarray: Array of feature vectors
        """
        return self.fit(flows).transform(flows)
    
    def _get_numeric_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract and preprocess numeric features from the dataframe.
        
        Args:
            df: Input DataFrame with flow data
            
        Returns:
            pd.DataFrame: DataFrame with numeric features
        """
        numeric_cols = [
            'src_port', 'dst_port', 'protocol', 'packet_count',
            'byte_count', 'flow_duration', 'packets_per_second',
            'bytes_per_second'
        ]
        
        # Only include columns that exist in the dataframe
        numeric_cols = [col for col in numeric_cols if col in df.columns]
        
        if not numeric_cols:
            return pd.DataFrame()
            
        numeric_df = df[numeric_cols].copy()
        
        # Ensure all values are numeric and handle any missing values
        for col in numeric_cols:
            numeric_df[col] = pd.to_numeric(numeric_df[col], errors='coerce')
        
        # Fill any remaining NaN values with column means
        return numeric_df.fillna(numeric_df.mean())
    
    @staticmethod
    def _safe_encode(encoder, values, default=None):
        """Safely encode values, handling unseen categories."""
        try:
            return encoder.transform(values)
        except ValueError:
            if default is not None and hasattr(encoder, 'classes_'):
                default_idx = len(encoder.classes_)
                if default not in encoder.classes_:
                    encoder.classes_ = np.append(encoder.classes_, default)
                return np.array([
                    np.where(encoder.classes_ == val)[0][0] 
                    if val in encoder.classes_ else default_idx 
                    for val in values
                ])
            raise


# Singleton instance
feature_extractor = FeatureExtractor()
