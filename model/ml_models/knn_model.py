"""
K-Nearest Neighbors Model for DDoS Detection
"""
from sklearn.neighbors import KNeighborsClassifier
from typing import Dict, Any

class KNNModel:
    """K-Nearest Neighbors classifier for DDoS detection."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the KNN model.
        
        Args:
            config: Model configuration parameters
        """
        default_config = {
            'n_neighbors': 5,
            'n_jobs': -1
        }
        
        if config:
            default_config.update(config)
            
        self.model = KNeighborsClassifier(**default_config)
    
    def get_model(self):
        """Get the underlying model instance."""
        return self.model
    
    def get_name(self) -> str:
        """Get the model name."""
        return "knn"
