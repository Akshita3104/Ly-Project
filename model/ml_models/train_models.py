"""
Model Training Script for DDoS Detection

This script trains multiple ML models for DDoS detection using collected traffic data.
"""
import os
import json
import time
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report
)

# Import models
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression

# Custom model imports
from decision_tree_model import DecisionTreeModel
from random_forest_model import RandomForestModel
from svm_model import SVMModel
from knn_model import KNNModel
from naive_bayes_model import NaiveBayesModel
from logistic_regression_model import LogisticRegressionModel

class ModelTrainer:
    """Handles training and evaluation of multiple ML models for DDoS detection."""
    
    def __init__(self, data_path, output_dir='models'):
        """
        Initialize the model trainer.
        
        Args:
            data_path: Path to the training data file
            output_dir: Directory to save trained models
        """
        self.data_path = data_path
        self.output_dir = output_dir
        self.models = {
            'decision_tree': DecisionTreeModel(),
            'random_forest': RandomForestModel(),
            'svm': SVMModel(),
            'knn': KNNModel(),
            'naive_bayes': NaiveBayesModel(),
            'logistic_regression': LogisticRegressionModel()
        }
        self.scaler = StandardScaler()
        self.results = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def load_data(self):
        """Load and preprocess the training data."""
        print(f"Loading data from {self.data_path}...")
        
        # Load data based on file extension
        if self.data_path.endswith('.csv'):
            data = pd.read_csv(self.data_path)
        elif self.data_path.endswith('.pkl') or self.data_path.endswith('.pickle'):
            with open(self.data_path, 'rb') as f:
                data = pickle.load(f)
        else:
            raise ValueError("Unsupported file format. Use CSV or pickle files.")
        
        # Preprocess data
        print("Preprocessing data...")
        
        # Assuming the data has 'label' column where 0=benign, 1=attack
        if 'label' not in data.columns:
            raise ValueError("Data must contain 'label' column (0=benign, 1=attack)")
        
        # Separate features and labels
        X = data.drop('label', axis=1)
        y = data['label']
        
        # Convert categorical features if any
        X = pd.get_dummies(X)
        
        # Split data into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_models(self):
        """Train all models and evaluate their performance."""
        # Load and preprocess data
        X_train, X_test, y_train, y_test = self.load_data()
        
        # Dictionary to store evaluation results
        self.results = {}
        
        # Train and evaluate each model
        for model_name, model in self.models.items():
            print(f"\n{'='*50}")
            print(f"Training {model_name}...")
            
            # Train the model
            start_time = time.time()
            model.train(X_train, y_train)
            training_time = time.time() - start_time
            
            # Make predictions
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            conf_matrix = confusion_matrix(y_test, y_pred).tolist()
            
            # Store results
            self.results[model_name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'confusion_matrix': conf_matrix,
                'training_time': training_time,
                'timestamp': datetime.now().isoformat()
            }
            
            # Print results
            print(f"\n{model_name.upper()} Results:")
            print(f"Accuracy: {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall: {recall:.4f}")
            print(f"F1 Score: {f1:.4f}")
            print(f"Training Time: {training_time:.2f} seconds")
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            print("\nConfusion Matrix:")
            print(conf_matrix)
            
            # Save the trained model
            self._save_model(model, model_name)
        
        # Save evaluation results
        self._save_results()
        
        return self.results
    
    def _save_model(self, model, model_name):
        """Save a trained model to disk."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"{model_name}_{timestamp}.pkl")
        
        # Create a dictionary with model and metadata
        model_data = {
            'model': model,
            'model_name': model_name,
            'timestamp': timestamp,
            'metrics': self.results.get(model_name, {})
        }
        
        # Save the model
        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Saved {model_name} model to {filename}")
    
    def _save_results(self):
        """Save evaluation results to a JSON file."""
        if not self.results:
            print("No results to save.")
            return
        
        # Convert numpy types to Python native types for JSON serialization
        def convert_numpy_types(obj):
            if isinstance(obj, (np.int_, np.intc, np.intp, np.int8,
                              np.int16, np.int32, np.int64, np.uint8,
                              np.uint16, np.uint32, np.uint64)):
                return int(obj)
            elif isinstance(obj, (np.float_, np.float16, np.float32, np.float64)):
                return float(obj)
            elif isinstance(obj, (np.ndarray,)):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_numpy_types(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy_types(item) for item in obj]
            return obj
        
        # Prepare results for saving
        results_to_save = convert_numpy_types(self.results)
        
        # Save to JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = os.path.join(self.output_dir, f"training_results_{timestamp}.json")
        
        with open(results_file, 'w') as f:
            json.dump(results_to_save, f, indent=4)
        
        print(f"\nSaved training results to {results_file}")

def train_models(data_path, output_dir='models'):
    """
    Train multiple ML models for DDoS detection.
    
    Args:
        data_path: Path to the training data file
        output_dir: Directory to save trained models
    """
    trainer = ModelTrainer(data_path, output_dir)
    return trainer.train_models()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Train DDoS Detection Models')
    parser.add_argument('data_path', help='Path to the training data file')
    parser.add_argument('-o', '--output-dir', default='models',
                      help='Directory to save trained models')
    
    args = parser.parse_args()
    
    train_models(args.data_path, args.output_dir)
