"""
Enhanced Decision Tree Model for Real-time DDoS Detection

This module implements a Decision Tree-based DDoS detection system with
real-time analysis, confidence scoring, and SDN integration capabilities.
"""
from datetime import datetime
from typing import Dict, Any, Tuple, List, Optional
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report
)
from collections import deque
import json

class DecisionTreeModel:
    """
    Enhanced Decision Tree model for DDoS detection with real-time capabilities.
    
    Features:
    - Real-time traffic analysis
    - Attack pattern recognition
    - Confidence scoring
    - Performance metrics tracking
    - SDN controller integration
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Enhanced Decision Tree model.
        
        Args:
            config: Model configuration parameters including:
                - max_depth: Maximum depth of the tree
                - min_samples_split: Minimum samples required to split a node
                - min_samples_leaf: Minimum samples required at a leaf node
                - class_weight: Class weights for imbalanced data
                - window_size: Size of the sliding window for real-time analysis
                - confidence_threshold: Threshold for attack classification
        """
        # Default configuration
        default_config = {
            'max_depth': 10,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42,
            'class_weight': 'balanced',
            'window_size': 100,  # For real-time analysis
            'confidence_threshold': 0.7
        }
        
        # Update with user config
        self.config = {**default_config, **(config or {})}
        
        # Initialize model
        model_params = {k: v for k, v in self.config.items() 
                       if k in ['max_depth', 'min_samples_split', 
                              'min_samples_leaf', 'random_state', 'class_weight']}
        self.model = DecisionTreeClassifier(**model_params)
        
        # Real-time analysis
        self.window_size = self.config['window_size']
        self.confidence_threshold = self.config['confidence_threshold']
        self.feature_window = deque(maxlen=self.window_size)
        self.label_window = deque(maxlen=self.window_size)
        
        # Performance tracking
        self.metrics = {}
        self.last_trained = None
        self.feature_importances_ = None
    
    def train(self, X: np.ndarray, y: np.ndarray, 
             test_size: float = 0.2) -> Dict[str, float]:
        """
        Train the model and evaluate on a test set.
        
        Args:
            X: Feature matrix
            y: Target labels (0 = normal, 1 = attack)
            test_size: Proportion of data to use for testing
            
        Returns:
            Dictionary of performance metrics
        """
        from sklearn.model_selection import train_test_split
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=self.config['random_state'],
            stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        self.last_trained = datetime.now()
        
        # Store feature importances
        self.feature_importances_ = dict(
            zip(range(X.shape[1]), self.model.feature_importances_)
        )
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        self.metrics = self._calculate_metrics(y_test, y_pred, y_proba)
        return self.metrics
    
    def predict(self, X: np.ndarray, return_proba: bool = False) -> np.ndarray:
        """
        Make predictions on new data.
        
        Args:
            X: Feature matrix
            return_proba: If True, return probability estimates
            
        Returns:
            Predicted labels or probabilities
        """
        if return_proba:
            return self.model.predict_proba(X)
        return self.model.predict(X)
    
    def detect_attack(self, flow_features: np.ndarray) -> Dict[str, Any]:
        """
        Detect DDoS attack in real-time flow features.
        
        Args:
            flow_features: Array of flow features for a single flow
            
        Returns:
            Dictionary containing:
                - is_attack: Boolean indicating if attack is detected
                - confidence: Confidence score (0-1)
                - attack_type: Type of attack if detected
        """
        # Ensure 2D array for single sample
        if len(flow_features.shape) == 1:
            flow_features = flow_features.reshape(1, -1)
            
        # Get prediction and confidence
        proba = self.model.predict_proba(flow_features)[0]
        pred = self.model.predict(flow_features)[0]
        confidence = max(proba)
        
        # Determine attack type (extend based on your classes)
        attack_type = "normal"
        if pred == 1 and confidence >= self.confidence_threshold:
            attack_type = self._classify_attack_type(flow_features)
        
        return {
            'is_attack': bool(pred == 1 and confidence >= self.confidence_threshold),
            'confidence': float(confidence),
            'attack_type': attack_type,
            'raw_prediction': int(pred),
            'proba': proba.tolist()
        }
    
    def update_with_feedback(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Update model with new labeled data and feedback.
        
        Args:
            X: New feature data
            y: New labels (0 = normal, 1 = attack)
            
        Returns:
            Updated performance metrics
        """
        # Add to sliding window
        for i in range(len(X)):
            self.feature_window.append(X[i])
            self.label_window.append(y[i])
        
        # Retrain if window is full
        if len(self.feature_window) >= self.window_size:
            X_retrain = np.array(self.feature_window)
            y_retrain = np.array(self.label_window)
            return self.train(X_retrain, y_retrain)
        
        return {}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and statistics."""
        return {
            'model_type': 'decision_tree',
            'parameters': self.model.get_params(),
            'feature_importances': self.feature_importances_,
            'last_trained': self.last_trained.isoformat() if self.last_trained else None,
            'metrics': self.metrics,
            'config': self.config
        }
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                          y_proba: np.ndarray) -> Dict[str, float]:
        """Calculate performance metrics."""
        return {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1': f1_score(y_true, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
            'classification_report': classification_report(y_true, y_pred, 
                                                         output_dict=True)
        }
    
    def _classify_attack_type(self, features: np.ndarray) -> str:
        """
        Classify the type of attack based on flow features.
        
        This is a placeholder - extend with your attack classification logic.
        """
        # Example: Simple threshold-based classification
        # You should replace this with your actual attack classification logic
        if features[0, 4] > 1000:  # Example: High packet rate
            return "volumetric_ddos"
        return "ddos"  # Default attack type
    
    def get_model(self):
        """Get the underlying scikit-learn model."""
        return self.model
    
    def get_name(self) -> str:
        """Get the model name."""
        return "decision_tree"
