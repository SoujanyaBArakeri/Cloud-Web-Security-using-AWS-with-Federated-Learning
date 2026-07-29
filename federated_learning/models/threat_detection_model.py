"""
Threat Detection Neural Network Model

A neural network classifier for detecting web security threats
from HTTP request features. Designed for federated learning.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, List
from .base_model import BaseModel


class ThreatDetectionModel(BaseModel):
    """
    Neural network for classifying HTTP requests as benign or malicious.

    Architecture:
    - Input: HTTP request features (14 features)
    - Hidden layers with batch normalization and dropout
    - Output: 5-class classification (benign, SQL injection, XSS, DDoS, bot)

    This model is designed to be trained in a federated manner,
    where each organization trains on their local data and shares
    only model updates (gradients), not the raw data.
    """

    NUM_CLASSES = 5
    CLASS_NAMES = ['benign', 'sql_injection', 'xss', 'ddos', 'bot']

    def __init__(
        self,
        input_dim: int = 14,
        hidden_dims: List[int] = None,
        dropout_rate: float = 0.3
    ):
        """
        Initialize the threat detection model.

        Args:
            input_dim: Number of input features
            hidden_dims: List of hidden layer dimensions
            dropout_rate: Dropout probability for regularization
        """
        super().__init__()

        if hidden_dims is None:
            hidden_dims = [64, 128, 64, 32]

        self.input_dim = input_dim
        self.hidden_dims = hidden_dims
        self.dropout_rate = dropout_rate

        layers = []
        prev_dim = input_dim

        for i, hidden_dim in enumerate(hidden_dims):
            layers.append(nn.Linear(prev_dim, hidden_dim))
            layers.append(nn.BatchNorm1d(hidden_dim))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(dropout_rate))
            prev_dim = hidden_dim

        self.feature_extractor = nn.Sequential(*layers)

        self.classifier = nn.Linear(prev_dim, self.NUM_CLASSES)

        self._init_weights()

    def _init_weights(self) -> None:
        """Initialize model weights using Xavier initialization."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass of the model.

        Args:
            x: Input tensor of shape (batch_size, input_dim)

        Returns:
            Logits tensor of shape (batch_size, num_classes)
        """
        features = self.feature_extractor(x)
        logits = self.classifier(features)
        return logits

    def predict(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Make predictions with confidence scores.

        Args:
            x: Input tensor of shape (batch_size, input_dim)

        Returns:
            Tuple of (predicted_classes, confidence_scores)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probabilities = F.softmax(logits, dim=1)
            confidence, predicted = torch.max(probabilities, dim=1)
        return predicted, confidence

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """
        Get probability distribution over classes.

        Args:
            x: Input tensor of shape (batch_size, input_dim)

        Returns:
            Probability tensor of shape (batch_size, num_classes)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probabilities = F.softmax(logits, dim=1)
        return probabilities

    def get_threat_name(self, class_idx: int) -> str:
        """
        Get the threat name for a class index.

        Args:
            class_idx: Class index (0-4)

        Returns:
            Threat name string
        """
        if 0 <= class_idx < len(self.CLASS_NAMES):
            return self.CLASS_NAMES[class_idx]
        return "unknown"

    @classmethod
    def get_feature_names(cls) -> List[str]:
        """
        Get the names of input features.

        Returns:
            List of feature names
        """
        return [
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


class ThreatDetectionModelLarge(ThreatDetectionModel):
    """
    Larger variant of the threat detection model for production use.

    Uses deeper architecture with more parameters for better accuracy.
    """

    def __init__(self, input_dim: int = 14, dropout_rate: float = 0.4):
        super().__init__(
            input_dim=input_dim,
            hidden_dims=[128, 256, 256, 128, 64],
            dropout_rate=dropout_rate
        )


class ThreatDetectionModelLight(ThreatDetectionModel):
    """
    Lightweight variant of the threat detection model.

    Optimized for edge deployment with fewer parameters.
    """

    def __init__(self, input_dim: int = 14, dropout_rate: float = 0.2):
        super().__init__(
            input_dim=input_dim,
            hidden_dims=[32, 64, 32],
            dropout_rate=dropout_rate
        )
