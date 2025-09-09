"""
Configuration settings for the DDoS detection system.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Model paths
MODEL_DIR = os.path.join(BASE_DIR, 'ml_models')
os.makedirs(MODEL_DIR, exist_ok=True)

# Data paths
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# Model parameters
MODEL_CONFIG = {
    'random_forest': {
        'n_estimators': 100,
        'max_depth': None,
        'random_state': 42,
        'n_jobs': -1
    },
    'decision_tree': {
        'max_depth': 10,
        'random_state': 42
    },
    'knn': {
        'n_neighbors': 5,
        'n_jobs': -1
    },
    'svm': {
        'C': 1.0,
        'kernel': 'rbf',
        'probability': True
    },
    'naive_bayes': {},
    'logistic_regression': {
        'max_iter': 1000,
        'random_state': 42,
        'n_jobs': -1
    }
}

# Feature configuration
FEATURES = [
    'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'protocol', 'packet_count', 'byte_count',
    'flow_duration', 'packets_per_second',
    'bytes_per_second', 'slice_id'
]

# Protocol mapping
PROTOCOL_MAP = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1,
    'other': 0
}

# Slice configuration
SLICE_CONFIG = {
    'default': 0,
    'high_priority': 1,
    'medium_priority': 2,
    'low_priority': 3
}

# Thresholds
DETECTION_THRESHOLD = 0.8  # Confidence threshold for attack detection
MITIGATION_THRESHOLD = 0.9  # Confidence threshold for auto-mitigation

# API Configuration
API_CONFIG = {
    'host': os.getenv('API_HOST', '0.0.0.0'),
    'port': int(os.getenv('API_PORT', 8000)),
    'debug': os.getenv('DEBUG', 'false').lower() == 'true'
}
