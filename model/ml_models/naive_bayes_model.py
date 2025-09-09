"""
Naive Bayes Model for DDoS Detection
"""
from sklearn.naive_bayes import GaussianNB
from typing import Dict, Any

class NaiveBayesModel:
    """Naive Bayes classifier for DDoS detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the Naive Bayes model.
        
        Args:
            config: Model configuration parameters
        """
        default_config = {}
        
        if config:
            default_config.update(config)
            
        self.model = GaussianNB(**default_config)
    
    def get_model(self):
        """Get the underlying model instance."""
        return self.model
    
    def get_name(self) -> str:
        """Get the model name."""
        return "naive_bayes"
