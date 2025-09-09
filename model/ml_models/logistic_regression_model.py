"""
Logistic Regression Model for DDoS Detection
"""
from sklearn.linear_model import LogisticRegression
from typing import Dict, Any

class LogisticRegressionModel:
    """Logistic Regression classifier for DDoS detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Logistic Regression model.
        
        Args:
            config: Model configuration parameters
        """
        default_config = {
            'max_iter': 1000,
            'random_state': 42,
            'n_jobs': -1,
            'class_weight': 'balanced'
        }
        
        if config:
            default_config.update(config)
            
        self.model = LogisticRegression(**default_config)
    
    def get_model(self):
        """Get the underlying model instance."""
        return self.model
    
    def get_name(self) -> str:
        """Get the model name."""
        return "logistic_regression"
