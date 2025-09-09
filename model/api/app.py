"""
SentinelAI API Server

This module provides the FastAPI application for the SentinelAI DDoS detection system.
"""
import logging
import logging.config
import time
import uvicorn
from fastapi import FastAPI, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import numpy as np

from config.system_config import (
    MODEL_CONFIG, 
    FRONTEND_CONFIG,
    API_CONFIG,
    MITIGATION_CONFIG,
    LOGGING_CONFIG
)
from ml_models.model_factory import model_factory

# Configure logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger('sentinelai.api')

# Initialize FastAPI app
app = FastAPI(
    title="SentinelAI API",
    description="API for DDoS detection and mitigation with multiple ML models",
    version=API_CONFIG['version']
)

# Initialize model factory
model_factory.create_model('decision_tree', MODEL_CONFIG.get('decision_tree', {}))

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class TrafficData(BaseModel):
    """Model for incoming traffic data."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    timestamp: str

class DetectionResult(BaseModel):
    """Model for detection results."""
    is_attack: bool
    confidence: float
    attack_type: Optional[str] = None
    timestamp: str
    source: str
    mitigation_action: Optional[str] = None

class MitigationRequest(BaseModel):
    """Model for mitigation requests."""
    target_ip: str
    action: str  # 'block', 'rate_limit', 'allow'
    duration: Optional[int] = None  # seconds

# State
class AppState:
    """Application state."""
    def __init__(self):
        self.detection_history = []
        self.mitigation_rules = {}
        self.active_model = 'decision_tree'
        self.model_metrics = {}
        self.system_metrics = {
            'total_requests': 0,
            'attack_count': 0,
            'false_positives': 0,
            'avg_processing_time': 0.0,
            'model_predictions': {},
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Initialize model metrics
        for model_type in model_factory.get_available_models():
            self.model_metrics[model_type] = {
                'total_predictions': 0,
                'true_positives': 0,
                'false_positives': 0,
                'true_negatives': 0,
                'false_negatives': 0,
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'last_updated': datetime.utcnow().isoformat()
            }

state = AppState()

# API Endpoints
@app.get(API_CONFIG['endpoints']['status'])
async def get_status(
    detailed: bool = Query(False, description="Include detailed model metrics")
):
    """
    Get system status and metrics.
    
    Args:
        detailed: If True, include detailed model metrics
    """
    response = {
        'status': 'operational',
        'version': API_CONFIG['version'],
        'active_model': state.active_model,
        'available_models': model_factory.get_available_models(),
        'mitigation_enabled': MITIGATION_CONFIG['enabled'],
        'system_metrics': state.system_metrics,
        'last_updated': state.system_metrics['last_updated']
    }
    
    if detailed:
        response['model_metrics'] = state.model_metrics
        
    return response

@app.get("/api/models")
async def list_models():
    """List all available models and their status."""
    models_info = {}
    for model_type in model_factory.get_available_models():
        models_info[model_type] = model_factory.get_model_info(model_type)
    
    return {
        'active_model': state.active_model,
        'models': models_info
    }

@app.post("/api/models/switch")
async def switch_model(model_type: str):
    """
    Switch the active model.
    
    Args:
        model_type: Type of model to switch to
    """
    try:
        model_factory.set_active_model(model_type)
        state.active_model = model_type
        return {"status": "success", "active_model": model_type}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@app.get("/api/models/{model_type}/info")
async def get_model_info(model_type: str):
    """
    Get information about a specific model.
    
    Args:
        model_type: Type of model to get info for
    """
    try:
        return model_factory.get_model_info(model_type)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@app.post(API_CONFIG['endpoints']['detect'])
async def detect_attack(traffic: TrafficData, model_type: str = None):
    """
    Analyze network traffic for DDoS attacks using the specified or active model.
    
    Args:
        traffic: Network traffic data
        model_type: Specific model to use (optional)
    """
    start_time = time.time()
    
    try:
        # Update metrics
        state.system_metrics['total_requests'] += 1
        
        # Convert traffic data to feature vector
        features = _extract_features(traffic)
        
        # Get the active model if none specified
        model_type = model_type or state.active_model
        model = model_factory.get_model(model_type)
        
        # Make prediction
        prediction = model.detect_attack(features)
        
        # Update detection history
        detection = {
            'timestamp': datetime.utcnow().isoformat(),
            'model': model_type,
            'src_ip': traffic.src_ip,
            'is_attack': prediction['is_attack'],
            'confidence': prediction['confidence'],
            'attack_type': prediction.get('attack_type')
        }
        state.detection_history.append(detection)
        
        # Update metrics
        _update_metrics(model_type, detection)
        
        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000  # in ms
        
        # Update average processing time
        total_time = state.system_metrics['avg_processing_time'] * \
                   (state.system_metrics['total_requests'] - 1) + processing_time
        state.system_metrics['avg_processing_time'] = \
            total_time / state.system_metrics['total_requests']
        
        state.system_metrics['last_updated'] = datetime.utcnow().isoformat()
        
        # Check if mitigation is needed
        mitigation_action = None
        if prediction['is_attack'] and MITIGATION_CONFIG['enabled']:
            mitigation_action = _apply_mitigation(
                traffic.src_ip, 
                prediction.get('attack_type')
            )
        
        return DetectionResult(
            is_attack=prediction['is_attack'],
            confidence=prediction['confidence'],
            attack_type=prediction.get('attack_type'),
            timestamp=detection['timestamp'],
            source=traffic.src_ip,
            model=model_type,
            processing_time_ms=processing_time,
            mitigation_action=mitigation_action
        )
        
    except Exception as e:
        logger.error(f"Error in detection: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post(API_CONFIG['endpoints']['mitigate'])
async def mitigate(request: MitigationRequest):
    """
    Apply mitigation actions.
    
    This endpoint allows manual triggering of mitigation actions.
    """
    try:
        if not MITIGATION_CONFIG['enabled']:
            return {"status": "mitigation_disabled"}
            
        # Apply mitigation
        result = self._apply_mitigation(
            request.target_ip,
            request.action,
            request.duration
        )
        
        return {"status": "success", "action": result}
        
    except Exception as e:
        logger.error(f"Error in mitigation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get(API_CONFIG['endpoints']['metrics'])
async def get_metrics():
    """Get detection metrics and statistics."""
    return {
        'system': state.system_metrics,
        'models': state.model_metrics
    }

    def _extract_features(traffic: TrafficData) -> np.ndarray:
        """
        Extract features from traffic data.
        
        Args:
            traffic: Traffic data
            
        Returns:
            Numpy array of features
        """
        # Convert traffic data to feature vector
        # This is a simplified example - adjust based on your actual features
        features = [
            traffic.packet_count,
            traffic.byte_count,
            # Add more features as needed
        ]
        return np.array([features])
    
    def _update_metrics(model_type: str, detection: Dict) -> None:
        """
        Update model and system metrics.
        
        Args:
            model_type: Type of model
            detection: Detection result
        """
        # Update model metrics
        metrics = state.model_metrics[model_type]
        metrics['total_predictions'] += 1
        
        # This is a simplified example - you'll need actual ground truth for real metrics
        # In a real system, you'd compare predictions with actual labels
        is_attack = detection['is_attack']
        
        if is_attack:
            state.system_metrics['attack_count'] += 1
            metrics['true_positives'] += 1
        else:
            metrics['true_negatives'] += 1
        
        # Update accuracy metrics
        total = metrics['true_positives'] + metrics['false_positives'] + \
                metrics['true_negatives'] + metrics['false_negatives']
        
        if total > 0:
            metrics['accuracy'] = (
                metrics['true_positives'] + metrics['true_negatives']
            ) / total
            
        if (metrics['true_positives'] + metrics['false_positives']) > 0:
            metrics['precision'] = metrics['true_positives'] / (
                metrics['true_positives'] + metrics['false_positives']
            )
            
        if (metrics['true_positives'] + metrics['false_negatives']) > 0:
            metrics['recall'] = metrics['true_positives'] / (
                metrics['true_positives'] + metrics['false_negatives']
            )
            
        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = 2 * (
                metrics['precision'] * metrics['recall']
            ) / (metrics['precision'] + metrics['recall'])
        
        metrics['last_updated'] = datetime.utcnow().isoformat()
        
        # Update model metrics in factory
        model_factory.update_metrics(model_type, metrics)

    def _apply_mitigation(ip: str, attack_type: str = None, duration: int = None) -> str:
        """Apply mitigation actions based on the attack type.
    
    Args:
        ip: Source IP to mitigate
        attack_type: Type of attack
        duration: Duration in seconds
        
    Returns:
        Action taken
    """
    if not duration:
        duration = MITIGATION_CONFIG.get('block_duration', 3600)
    
    action = None
    
    # Choose mitigation action based on attack type
    if MITIGATION_CONFIG['actions']['block_ip']:
        action = f"block_ip:{ip}:{duration}"
        # TODO: Implement actual blocking (e.g., iptables)
        logger.info(f"Blocking IP {ip} for {duration} seconds")
    
    # Store mitigation rule
    state.mitigation_rules[ip] = {
        'action': action,
        'applied_at': datetime.utcnow().isoformat(),
        'expires_at': (datetime.utcnow() + timedelta(seconds=duration)).isoformat(),
        'attack_type': attack_type
    }
    
    return action

def start_api():
    """Start the API server."""
    logger.info(f"Starting SentinelAI API on {FRONTEND_CONFIG['host']}:{FRONTEND_CONFIG['port']}")
    uvicorn.run(
        app,
        host=FRONTEND_CONFIG['host'],
        port=FRONTEND_CONFIG['port'],
        log_level="info" if FRONTEND_CONFIG['debug'] else "warning"
    )

if __name__ == "__main__":
    start_api()
