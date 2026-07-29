"""
Data Preprocessor for Federated Learning

Processes HTTP request logs into feature vectors suitable for
training the threat detection model.
"""

import json
import os
from typing import List, Dict, Tuple, Optional
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader


class ThreatDataset(Dataset):
    """PyTorch Dataset for threat detection training data."""

    LABEL_MAP = {
        'benign': 0,
        'sql_injection': 1,
        'xss': 2,
        'ddos': 3,
        'bot': 4
    }

    def __init__(self, features: np.ndarray, labels: np.ndarray):
        """
        Initialize the dataset.

        Args:
            features: Feature array of shape (n_samples, n_features)
            labels: Label array of shape (n_samples,)
        """
        self.features = torch.FloatTensor(features)
        self.labels = torch.LongTensor(labels)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.features[idx], self.labels[idx]


class DataPreprocessor:
    """
    Preprocesses HTTP request logs for model training.

    Handles:
    - Loading JSONL log files
    - Feature extraction and normalization
    - Train/validation splitting
    - DataLoader creation
    """

    FEATURE_NAMES = [
        'method_encoded',
        'path_depth',
        'path_length',
        'body_length',
        'query_length',
        'header_count',
        'special_chars_body',
        'special_chars_query',
        'sql_keyword_count',
        'xss_keyword_count',
        'has_user_agent',
        'user_agent_length',
        'content_type_json',
        'has_auth_header',
    ]

    def __init__(self, data_path: str):
        """
        Initialize the preprocessor.

        Args:
            data_path: Path to directory containing log files
        """
        self.data_path = data_path
        self.feature_stats: Dict[str, Dict[str, float]] = {}

    def load_logs(self, file_pattern: str = "*.jsonl") -> List[Dict]:
        """
        Load request logs from JSONL files.

        Args:
            file_pattern: Glob pattern for log files

        Returns:
            List of log entries
        """
        import glob

        logs = []
        pattern = os.path.join(self.data_path, file_pattern)

        for filepath in glob.glob(pattern):
            with open(filepath, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if 'features' in entry:
                            logs.append(entry)
                    except json.JSONDecodeError:
                        continue

        return logs

    def extract_features(self, logs: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extract feature vectors and labels from logs.

        Args:
            logs: List of log entries

        Returns:
            Tuple of (features_array, labels_array)
        """
        features_list = []
        labels_list = []

        for entry in logs:
            feature_dict = entry.get('features', {})
            label = entry.get('label', 'benign')

            feature_vector = [
                feature_dict.get(name, 0) for name in self.FEATURE_NAMES
            ]
            features_list.append(feature_vector)

            label_idx = ThreatDataset.LABEL_MAP.get(label, 0)
            labels_list.append(label_idx)

        return np.array(features_list, dtype=np.float32), np.array(labels_list)

    def normalize_features(
        self,
        features: np.ndarray,
        fit: bool = True
    ) -> np.ndarray:
        """
        Normalize features using z-score normalization.

        Args:
            features: Feature array
            fit: Whether to compute statistics from this data

        Returns:
            Normalized feature array
        """
        if fit:
            self.feature_stats = {
                'mean': np.mean(features, axis=0),
                'std': np.std(features, axis=0) + 1e-8
            }

        normalized = (features - self.feature_stats['mean']) / self.feature_stats['std']
        return normalized

    def create_dataloaders(
        self,
        batch_size: int = 32,
        val_split: float = 0.2,
        shuffle: bool = True
    ) -> Tuple[DataLoader, DataLoader, int]:
        """
        Create train and validation DataLoaders.

        Args:
            batch_size: Batch size for training
            val_split: Fraction of data for validation
            shuffle: Whether to shuffle training data

        Returns:
            Tuple of (train_loader, val_loader, num_samples)
        """
        logs = self.load_logs()

        if not logs:
            return self._create_synthetic_data(batch_size)

        features, labels = self.extract_features(logs)
        features = self.normalize_features(features)

        n_samples = len(labels)
        n_val = int(n_samples * val_split)
        indices = np.random.permutation(n_samples)

        val_indices = indices[:n_val]
        train_indices = indices[n_val:]

        train_dataset = ThreatDataset(features[train_indices], labels[train_indices])
        val_dataset = ThreatDataset(features[val_indices], labels[val_indices])

        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=shuffle
        )
        val_loader = DataLoader(
            val_dataset,
            batch_size=batch_size,
            shuffle=False
        )

        return train_loader, val_loader, len(train_indices)

    def _create_synthetic_data(
        self,
        batch_size: int
    ) -> Tuple[DataLoader, DataLoader, int]:
        """
        Create synthetic data for testing when no real data available.

        Returns:
            Tuple of (train_loader, val_loader, num_samples)
        """
        np.random.seed(42)
        n_samples = 1000

        features = np.random.randn(n_samples, len(self.FEATURE_NAMES)).astype(np.float32)
        labels = np.random.randint(0, 5, n_samples)

        for i in range(n_samples):
            if labels[i] == 1:
                features[i, 8] = np.random.uniform(2, 5)
            elif labels[i] == 2:
                features[i, 9] = np.random.uniform(2, 5)
            elif labels[i] == 3:
                features[i, 3] = np.random.uniform(5, 10)
                features[i, 4] = np.random.uniform(5, 10)

        n_val = int(n_samples * 0.2)
        train_dataset = ThreatDataset(features[n_val:], labels[n_val:])
        val_dataset = ThreatDataset(features[:n_val], labels[:n_val])

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

        return train_loader, val_loader, n_samples - n_val

    def get_class_weights(self, labels: np.ndarray) -> torch.Tensor:
        """
        Compute class weights for imbalanced datasets.

        Args:
            labels: Label array

        Returns:
            Tensor of class weights
        """
        class_counts = np.bincount(labels, minlength=5)
        total = len(labels)
        weights = total / (len(class_counts) * class_counts + 1e-8)
        return torch.FloatTensor(weights)
