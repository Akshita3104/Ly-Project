"""
Support Vector Machine Model for DDoS Detection
"""
from sklearn.svm import SVC
from typing import Dict, Any

class SVMModel:
    """Support Vector Machine classifier for DDoS detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the SVM model.
        
        Args:
            config: Model configuration parameters
        """
        default_config = {
            'C': 1.0,
            'kernel': 'rbf', 
            'probability': True,
            'class_weight': 'balanced',
            'random_state': 42
        }
        
        if config:
            default_config.update(config)
            
        self.model = SVC(**default_config)
    
    def get_model(self):
        """Get the underlying model instance."""
        return self.model
    
    def get_name(self) -> str:
        """Get the model name."""
        return "svm"
