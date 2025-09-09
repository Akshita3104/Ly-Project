"""
Model Factory for DDoS Detection

This module provides a factory for creating and managing multiple ML models.
"""
import importlib
import logging
from typing import Dict, Type, Any, List, Optional
from pathlib import Path
import json

from .base_model import BaseModel
from ..config.system_config import MODEL_DIR

logger = logging.getLogger('sentinelai.model_factory')

class ModelFactory:
    """Factory for creating and managing ML models."""
    
    def __init__(self):
        self.models: Dict[str, BaseModel] = {}
        self.available_models = {
            'decision_tree': 'decision_tree_model.DecisionTreeModel',
            'random_forest': 'random_forest_model.RandomForestModel',
            'svm': 'svm_model.SVMModel',
            'knn': 'knn_model.KNNModel',
            'naive_bayes': 'naive_bayes_model.NaiveBayesModel',
            'logistic_regression': 'logistic_regression_model.LogisticRegressionModel'
        }
        self.active_model: Optional[str] = None
        self.model_metrics: Dict[str, Dict] = {}
    
    def create_model(self, model_type: str, config: Dict[str, Any] = None) -> BaseModel:
        """
        Create a new model instance.
        
        Args:
            model_type: Type of model to create
            config: Model configuration
            
        Returns:
            Instance of the created model
            
        Raises:
            ValueError: If model type is not supported
        """
        if model_type not in self.available_models:
            raise ValueError(f"Unsupported model type: {model_type}")
            
        try:
            # Dynamically import the model class
            module_name, class_name = self.available_models[model_type].split('.')
            module = importlib.import_module(f"ml_models.{module_name}")
            model_class = getattr(module, class_name)
            
            # Create model instance
            model = model_class(config or {})
            self.models[model_type] = model
            
            # Set as active if no active model
            if self.active_model is None:
                self.active_model = model_type
                
            logger.info(f"Created {model_type} model")
            return model
            
        except Exception as e:
            logger.error(f"Error creating {model_type} model: {e}")
            raise
    
    def get_model(self, model_type: str = None) -> BaseModel:
        """
        Get a model instance.
        
        Args:
            model_type: Type of model to get (None for active model)
            
        Returns:
            The requested model instance
            
        Raises:
            ValueError: If model type is not found
        """
        model_type = model_type or self.active_model
        if model_type is None:
            raise ValueError("No active model set")
            
        if model_type not in self.models:
            self.create_model(model_type)
            
        return self.models[model_type]
    
    def set_active_model(self, model_type: str) -> None:
        """
        Set the active model.
        
        Args:
            model_type: Type of model to set as active
            
        Raises:
            ValueError: If model type is not available
        """
        if model_type not in self.available_models:
            raise ValueError(f"Unsupported model type: {model_type}")
            
        if model_type not in self.models:
            self.create_model(model_type)
            
        self.active_model = model_type
        logger.info(f"Active model set to: {model_type}")
    
    def get_available_models(self) -> List[str]:
        """Get list of available model types."""
        return list(self.available_models.keys())
    
    def get_model_info(self, model_type: str = None) -> Dict[str, Any]:
        """
        Get information about a model.
        
        Args:
            model_type: Type of model (None for active model)
            
        Returns:
            Dictionary containing model information
        """
        model = self.get_model(model_type)
        return {
            'model_type': model.get_name(),
            'parameters': model.get_params(),
            'metrics': self.model_metrics.get(model.get_name(), {}),
            'is_active': (model_type or self.active_model) == self.active_model
        }
    
    def update_metrics(self, model_type: str, metrics: Dict[str, Any]) -> None:
        """
        Update performance metrics for a model.
        
        Args:
            model_type: Type of model
            metrics: Dictionary of metrics
        """
        if model_type not in self.model_metrics:
            self.model_metrics[model_type] = {}
        self.model_metrics[model_type].update(metrics)
    
    def save_model(self, model_type: str, filename: str = None) -> str:
        """
        Save a trained model to disk.
        
        Args:
            model_type: Type of model to save
            filename: Output filename (optional)
            
        Returns:
            Path to the saved model file
        """
        model = self.get_model(model_type)
        
        if not filename:
            filename = f"{model_type}_model_{model.get_name()}.pkl"
            
        filepath = MODEL_DIR / filename
        
        # Save model and metadata
        model_data = {
            'model_type': model_type,
            'model': model,
            'metrics': self.model_metrics.get(model_type, {}),
            'config': model.get_params()
        }
        
        with open(filepath, 'wb') as f:
            import pickle
            pickle.dump(model_data, f)
            
        logger.info(f"Saved {model_type} model to {filepath}")
        return str(filepath)
    
    def load_model(self, filepath: str) -> str:
        """
        Load a trained model from disk.
        
        Args:
            filepath: Path to the model file
            
        Returns:
            Type of the loaded model
            
        Raises:
            FileNotFoundError: If model file doesn't exist
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
            
        with open(filepath, 'rb') as f:
            import pickle
            model_data = pickle.load(f)
            
        model_type = model_data['model_type']
        self.models[model_type] = model_data['model']
        
        if 'metrics' in model_data:
            self.model_metrics[model_type] = model_data['metrics']
            
        logger.info(f"Loaded {model_type} model from {filepath}")
        return model_type

# Singleton instance
model_factory = ModelFactory()
