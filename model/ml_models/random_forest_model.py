"""
Random Forest Model for DDoS Detection
"""
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Any

class RandomForestModel:
    """Random Forest classifier for DDoS detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Random Forest model.
        
        Args:
            config: Model configuration parameters
        """
        default_config = {
            'n_estimators': 100,
            'max_depth': None,
            'random_state': 42,
            'n_jobs': -1,
            'class_weight': 'balanced'
        }
        
        if config:
            default_config.update(config)
            
        self.model = RandomForestClassifier(**default_config)
    
    def get_model(self):
        """Get the underlying model instance."""
        return self.model
    
    def get_name(self) -> str:
        """Get the model name."""
        return "random_forest"
