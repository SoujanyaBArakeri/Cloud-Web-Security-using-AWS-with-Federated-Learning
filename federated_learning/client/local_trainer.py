"""
Local Trainer for Federated Learning Clients

Handles local model training on organization-specific data
and communication with the aggregation server.
"""

import os
import io
import base64
import logging
import requests
from typing import Dict, Optional, Tuple
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader

from ..models.threat_detection_model import ThreatDetectionModel
from .data_preprocessor import DataPreprocessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LocalTrainer:
    """
    Local trainer for federated learning clients.

    Each organization runs a LocalTrainer that:
    1. Downloads the global model from the server
    2. Trains locally on private data
    3. Uploads model updates (not raw data) to the server
    """

    def __init__(
        self,
        org_id: str,
        server_host: str = "localhost",
        server_port: int = 8080,
        data_path: str = "data",
        local_epochs: int = 5,
        learning_rate: float = 0.001,
        batch_size: int = 32
    ):
        """
        Initialize the local trainer.

        Args:
            org_id: Unique identifier for this organization
            server_host: FL server hostname
            server_port: FL server port
            data_path: Path to local training data
            local_epochs: Number of local training epochs per round
            learning_rate: Learning rate for local training
            batch_size: Batch size for local training
        """
        self.org_id = org_id
        self.server_url = f"http://{server_host}:{server_port}"
        self.data_path = data_path
        self.local_epochs = local_epochs
        self.learning_rate = learning_rate
        self.batch_size = batch_size

        self.model = ThreatDetectionModel()
        self.preprocessor = DataPreprocessor(data_path)

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

        self.is_registered = False
        self.current_round = 0

    def register(self) -> bool:
        """
        Register with the aggregation server.

        Returns:
            True if registration successful
        """
        try:
            response = requests.post(
                f"{self.server_url}/register",
                json={'client_id': self.org_id},
                timeout=30
            )
            if response.status_code == 200:
                self.is_registered = True
                data = response.json()
                self.current_round = data.get('current_round', 0)
                logger.info(f"Registered with server: {self.org_id}")
                return True
            else:
                logger.error(f"Registration failed: {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Failed to connect to server: {e}")
            return False

    def download_model(self) -> bool:
        """
        Download the current global model from the server.

        Returns:
            True if download successful
        """
        try:
            response = requests.get(
                f"{self.server_url}/model",
                timeout=60
            )
            if response.status_code == 200:
                data = response.json()
                model_bytes = base64.b64decode(data['model'])
                buffer = io.BytesIO(model_bytes)
                state_dict = torch.load(buffer, weights_only=True)
                self.model.load_state_dict(state_dict)
                self.current_round = data.get('round', 0)
                logger.info(f"Downloaded model (round {self.current_round})")
                return True
            else:
                logger.error(f"Model download failed: {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Failed to download model: {e}")
            return False

    def train_local(self) -> Tuple[Dict[str, torch.Tensor], int, Dict]:
        """
        Train model on local data.

        Returns:
            Tuple of (model_weights, num_samples, metrics)
        """
        train_loader, val_loader, num_samples = self.preprocessor.create_dataloaders(
            batch_size=self.batch_size
        )

        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)

        self.model.train()
        train_losses = []

        for epoch in range(self.local_epochs):
            epoch_loss = 0.0
            num_batches = 0

            for features, labels in train_loader:
                features = features.to(self.device)
                labels = labels.to(self.device)

                optimizer.zero_grad()
                outputs = self.model(features)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                num_batches += 1

            avg_loss = epoch_loss / max(num_batches, 1)
            train_losses.append(avg_loss)
            logger.info(f"Epoch {epoch + 1}/{self.local_epochs}, Loss: {avg_loss:.4f}")

        val_accuracy = self._evaluate(val_loader)

        weights = {
            name: param.data.clone()
            for name, param in self.model.named_parameters()
        }

        metrics = {
            'loss': train_losses[-1] if train_losses else 0,
            'accuracy': val_accuracy,
            'epochs': self.local_epochs
        }

        return weights, num_samples, metrics

    def _evaluate(self, val_loader: DataLoader) -> float:
        """Evaluate model on validation data."""
        self.model.eval()
        correct = 0
        total = 0

        with torch.no_grad():
            for features, labels in val_loader:
                features = features.to(self.device)
                labels = labels.to(self.device)

                outputs = self.model(features)
                _, predicted = torch.max(outputs, 1)

                total += labels.size(0)
                correct += (predicted == labels).sum().item()

        accuracy = correct / max(total, 1)
        logger.info(f"Validation accuracy: {accuracy:.4f}")
        return accuracy

    def upload_update(
        self,
        weights: Dict[str, torch.Tensor],
        num_samples: int,
        metrics: Dict
    ) -> bool:
        """
        Upload model update to the server.

        Args:
            weights: Trained model weights
            num_samples: Number of samples used for training
            metrics: Training metrics

        Returns:
            True if upload successful
        """
        try:
            buffer = io.BytesIO()
            torch.save(weights, buffer)
            weights_bytes = buffer.getvalue()
            weights_b64 = base64.b64encode(weights_bytes).decode('utf-8')

            response = requests.post(
                f"{self.server_url}/update",
                json={
                    'client_id': self.org_id,
                    'weights': weights_b64,
                    'num_samples': num_samples,
                    'metrics': metrics
                },
                timeout=60
            )

            if response.status_code == 200:
                logger.info(f"Upload successful for round {self.current_round}")
                return True
            else:
                logger.error(f"Upload failed: {response.text}")
                return False

        except requests.RequestException as e:
            logger.error(f"Failed to upload update: {e}")
            return False

    def participate_round(self) -> bool:
        """
        Participate in one round of federated learning.

        Returns:
            True if round completed successfully
        """
        if not self.is_registered:
            if not self.register():
                return False

        if not self.download_model():
            return False

        weights, num_samples, metrics = self.train_local()

        if not self.upload_update(weights, num_samples, metrics):
            return False

        self.current_round += 1
        return True

    def run(self, num_rounds: Optional[int] = None) -> None:
        """
        Run the federated learning client.

        Args:
            num_rounds: Number of rounds to participate in (None = forever)
        """
        rounds_completed = 0

        while num_rounds is None or rounds_completed < num_rounds:
            logger.info(f"Starting round {rounds_completed + 1}")

            if self.participate_round():
                rounds_completed += 1
                logger.info(f"Completed round {rounds_completed}")
            else:
                logger.warning("Round failed, retrying...")
                import time
                time.sleep(5)

        logger.info(f"Completed {rounds_completed} rounds of training")


def main():
    """Main entry point for the FL client."""
    org_id = os.environ.get('ORG_ID', 'client_1')
    server_host = os.environ.get('FL_SERVER_HOST', 'localhost')
    server_port = int(os.environ.get('FL_SERVER_PORT', 8080))
    data_path = os.environ.get('DATA_PATH', 'data')
    local_epochs = int(os.environ.get('LOCAL_EPOCHS', 5))

    trainer = LocalTrainer(
        org_id=org_id,
        server_host=server_host,
        server_port=server_port,
        data_path=data_path,
        local_epochs=local_epochs
    )

    trainer.run()


if __name__ == '__main__':
    main()
