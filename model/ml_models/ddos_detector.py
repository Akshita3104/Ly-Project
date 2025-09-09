"""
DDoS Detector Module

This module implements a unified interface for DDoS detection using various ML models.
"""
import logging
import os
import pickle
import importlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union, Type, Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from sklearn.model_selection import train_test_split

from ..config.config import MODEL_DIR, DETECTION_THRESHOLD

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import model classes
MODEL_MAPPING = {
    'random_forest': 'random_forest_model.RandomForestModel',
    'decision_tree': 'decision_tree_model.DecisionTreeModel',
    'knn': 'knn_model.KNNModel',
    'svm': 'svm_model.SVMModel',
    'naive_bayes': 'naive_bayes_model.NaiveBayesModel',
    'logistic_regression': 'logistic_regression_model.LogisticRegressionModel'
}

def load_model_class(model_type: str) -> Any:
    """Dynamically load a model class by type."""
    if model_type not in MODEL_MAPPING:
        raise ValueError(f"Unsupported model type: {model_type}")
    
    module_name, class_name = MODEL_MAPPING[model_type].split('.')
    module = importlib.import_module(f"model.ml_models.{module_name}")
    return getattr(module, class_name)

class DDoSDetector:
    """
    Machine learning-based DDoS detection system.
    
    This class provides a unified interface for training and using multiple ML models
    for DDoS detection in network traffic.
    """
    
    def __init__(self, model_type: str = 'random_forest', model_config: Optional[Dict] = None):
        """
        Initialize the DDoS detector with a specific model type.
        
        Args:
            model_type: Type of model to use (see MODEL_MAPPING for supported types)
            model_config: Optional configuration parameters for the model
        """
        self.model_type = model_type.lower()
        self.model_wrapper = self._init_model(model_config or {})
        self.model = self.model_wrapper.get_model()
        self.feature_importances_ = None
        self.classes_ = None
        self.trained_at = None
        self.metrics = {}
    
    def _init_model(self, config: Dict) -> Any:
        """
        Initialize the specified ML model.
        
        Args:
            config: Configuration parameters for the model
            
        Returns:
            An instance of the specified model
        """
        model_class = load_model_class(self.model_type)
        return model_class(config)
    
    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2, 
             random_state: int = 42) -> Dict:
        """
        Train the DDoS detection model.
        
        Args:
            X: Feature matrix
            y: Target labels (0 = normal, 1 = attack)
            test_size: Proportion of data to use for testing
            random_state: Random seed for reproducibility
            
        Returns:
            Dict: Training metrics
        """
        try:
            # Split data into training and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            # Train the model
            self.model.fit(X_train, y_train)
            self.classes_ = self.model.classes_
            self.trained_at = datetime.utcnow()
            
            # Evaluate on test set
            y_pred = self.model.predict(X_test)
            y_proba = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, 'predict_proba') else None
            
            # Calculate metrics
            metrics = self._calculate_metrics(y_test, y_pred, y_proba)
            self.metrics = metrics
            
            # Store feature importances if available
            if hasattr(self.model, 'feature_importances_'):
                self.feature_importances_ = self.model.feature_importances_
            
            logger.info(f"{self.model_wrapper.get_name().upper()} model trained successfully. "
                       f"Accuracy: {metrics['accuracy']:.4f}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise
    
    def predict(self, X: np.ndarray, return_proba: bool = False) -> np.ndarray:
        """
        Make predictions on new data.
        
        Args:
            X: Feature matrix
            return_proba: Whether to return probability estimates
            
        Returns:
            np.ndarray: Predicted labels or probabilities
        """
        if return_proba and hasattr(self.model, 'predict_proba'):
            return self.model.predict_proba(X)
        return self.model.predict(X)
    
    def detect_ddos(self, flow_features: np.ndarray) -> Tuple[bool, float]:
        """
        Detect DDoS attack in flow features.
        
        Args:
            flow_features: Preprocessed flow features
            
        Returns:
            Tuple[bool, float]: (is_attack, confidence)
        """
        if not hasattr(self.model, 'predict_proba'):
            pred = self.model.predict(flow_features.reshape(1, -1))[0]
            return bool(pred), 1.0 if pred else 0.0
        
        proba = self.model.predict_proba(flow_features.reshape(1, -1))[0]
        attack_prob = proba[1] if len(proba) > 1 else proba[0]
        is_attack = attack_prob >= DETECTION_THRESHOLD
        return is_attack, float(attack_prob if is_attack else (1 - attack_prob))
    
    def save(self, filename: Optional[str] = None) -> str:
        """
        Save the trained model to disk.
        
        Args:
            filename: Output filename (optional)
            
        Returns:
            str: Path to the saved model file
        """
        if not os.path.exists(MODEL_DIR):
            os.makedirs(MODEL_DIR)
            
        if filename is None:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"ddos_detector_{self.model_wrapper.get_name()}_{timestamp}.pkl"
            
        filepath = os.path.join(MODEL_DIR, filename)
        
        # Save the model with metadata
        model_data = {
            'model': self.model,
            'model_type': self.model_type,
            'model_wrapper': self.model_wrapper,
            'feature_importances': self.feature_importances_,
            'classes': self.classes_,
            'trained_at': self.trained_at,
            'metrics': self.metrics
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
            
        logger.info(f"{self.model_wrapper.get_name().upper()} model saved to {filepath}")
        return filepath
    
    @classmethod
    def load(cls, filepath: str) -> 'DDoSDetector':
        """
        Load a trained model from disk.
        
        Args:
            filepath: Path to the saved model file
            
        Returns:
            DDoSDetector: Loaded model instance
        """
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        detector = cls(model_data['model_type'])
        detector.model = model_data['model']
        detector.model_wrapper = model_data.get('model_wrapper', detector.model_wrapper)
        detector.feature_importances_ = model_data.get('feature_importances')
        detector.classes_ = model_data.get('classes')
        detector.trained_at = model_data.get('trained_at')
        detector.metrics = model_data.get('metrics', {})
        
        model_name = detector.model_wrapper.get_name() if hasattr(detector, 'model_wrapper') else 'unknown'
        logger.info(f"{model_name.upper()} model loaded from {filepath}")
        return detector
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                          y_proba: Optional[np.ndarray] = None) -> Dict:
        """
        Calculate performance metrics.
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_proba: Predicted probabilities (optional)
            
        Returns:
            Dict: Dictionary of metrics
        """
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1': f1_score(y_true, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
            'classification_report': classification_report(y_true, y_pred, output_dict=True)
        }
        
        return metrics
    
    def get_feature_importance(self, feature_names: List[str] = None) -> Dict:
        """
        Get feature importances if available.
        
        Args:
            feature_names: List of feature names
            
        Returns:
            Dict: Dictionary of feature importances
        """
        if self.feature_importances_ is None:
            return {}
            
        if feature_names is None:
            feature_names = [f'feature_{i}' for i in range(len(self.feature_importances_))]
        
        return dict(zip(feature_names, self.feature_importances_))
