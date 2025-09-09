"""
System Configuration for DDoS Detection and Mitigation
"""
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.parent
MODEL_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"

# Ensure directories exist
for directory in [MODEL_DIR, DATA_DIR, LOG_DIR]:
    directory.mkdir(exist_ok=True, parents=True)

# Model configuration
MODEL_CONFIG = {
    'model_type': 'decision_tree',  # Default model
    'decision_tree': {
        'max_depth': 15,
        'min_samples_split': 5,
        'min_samples_leaf': 2,
        'class_weight': 'balanced',
        'window_size': 100,
        'confidence_threshold': 0.7
    },
    'update_interval': 300  # Update model every 5 minutes with new data
}

# Frontend configuration
FRONTEND_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': True
}

# API Configuration
API_CONFIG = {
    'endpoints': {
        'detect': '/api/detect',
        'status': '/api/status',
        'mitigate': '/api/mitigate',
        'metrics': '/api/metrics'
    },
    'rate_limit': '1000/day',
    'version': '1.0'
}

# Traffic collection settings
TRAFFIC_CONFIG = {
    'sampling_interval': 5,  # seconds
    'max_samples': 1000,     # Max samples to keep in memory
    'features': [
        'src_ip',
        'dst_ip',
        'src_port',
        'dst_port',
        'protocol',
        'packet_count',
        'byte_count',
        'duration_sec',
        'flow_count',
        'packet_rate',
        'byte_rate'
    ]
}

# Mitigation settings
MITIGATION_CONFIG = {
    'enabled': True,
    'actions': {
        'block_ip': True,
        'rate_limit': True,
        'redirect': False
    },
    'block_duration': 3600,  # seconds (1 hour)
    'rate_limit_threshold': 1000,  # packets per second
    'notification_emails': []  # List of emails to notify
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': str(LOG_DIR / 'sentinelai.log'),
            'formatter': 'standard'
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
    },
    'loggers': {
        'sentinelai': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True
        }
    }
}
