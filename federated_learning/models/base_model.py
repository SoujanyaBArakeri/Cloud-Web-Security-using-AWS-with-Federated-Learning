"""
Base Model for Federated Learning

Provides the foundation for ML models used in the federated learning system.
"""

import torch
import torch.nn as nn
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
import copy


class BaseModel(nn.Module, ABC):
    """
    Abstract base class for federated learning models.

    All threat detection models should inherit from this class
    to ensure compatibility with the federated learning framework.
    """

    def __init__(self):
        super().__init__()
        self._version = "1.0.0"

    @abstractmethod
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass of the model."""
        pass

    def get_weights(self) -> Dict[str, torch.Tensor]:
        """
        Get model weights as a dictionary.

        Returns:
            Dictionary mapping parameter names to tensors
        """
        return {name: param.data.clone() for name, param in self.named_parameters()}

    def set_weights(self, weights: Dict[str, torch.Tensor]) -> None:
        """
        Set model weights from a dictionary.

        Args:
            weights: Dictionary mapping parameter names to tensors
        """
        state_dict = self.state_dict()
        for name, param in weights.items():
            if name in state_dict:
                state_dict[name] = param
        self.load_state_dict(state_dict)

    def get_gradients(self) -> Dict[str, torch.Tensor]:
        """
        Get model gradients as a dictionary.

        Returns:
            Dictionary mapping parameter names to gradient tensors
        """
        gradients = {}
        for name, param in self.named_parameters():
            if param.grad is not None:
                gradients[name] = param.grad.clone()
        return gradients

    def apply_gradients(
        self,
        gradients: Dict[str, torch.Tensor],
        learning_rate: float = 0.01
    ) -> None:
        """
        Apply gradients to model parameters.

        Args:
            gradients: Dictionary of gradients
            learning_rate: Learning rate for gradient application
        """
        with torch.no_grad():
            for name, param in self.named_parameters():
                if name in gradients:
                    param -= learning_rate * gradients[name]

    def clone(self) -> 'BaseModel':
        """
        Create a deep copy of the model.

        Returns:
            A new model instance with the same weights
        """
        return copy.deepcopy(self)

    def count_parameters(self) -> int:
        """
        Count the total number of trainable parameters.

        Returns:
            Number of trainable parameters
        """
        return sum(p.numel() for p in self.parameters() if p.requires_grad)

    def save(self, path: str) -> None:
        """
        Save model to file.

        Args:
            path: File path to save the model
        """
        torch.save({
            'model_state_dict': self.state_dict(),
            'version': self._version,
        }, path)

    def load(self, path: str) -> None:
        """
        Load model from file.

        Args:
            path: File path to load the model from
        """
        checkpoint = torch.load(path, weights_only=True)
        self.load_state_dict(checkpoint['model_state_dict'])
        self._version = checkpoint.get('version', '1.0.0')

    @property
    def version(self) -> str:
        """Get model version."""
        return self._version

    @version.setter
    def version(self, value: str) -> None:
        """Set model version."""
        self._version = value
