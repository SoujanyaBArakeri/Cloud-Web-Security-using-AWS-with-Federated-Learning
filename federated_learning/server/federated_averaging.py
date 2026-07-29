"""
Federated Averaging Algorithm

Implements the FedAvg algorithm for aggregating model updates
from multiple clients without accessing their raw data.
"""

import torch
from typing import Dict, List, Optional, Tuple
import copy
import logging

logger = logging.getLogger(__name__)


class FederatedAveraging:
    """
    Federated Averaging (FedAvg) implementation.

    This algorithm aggregates model updates from multiple clients by
    computing a weighted average of their model parameters. The weights
    are based on the number of training samples each client used.

    Reference: McMahan et al., "Communication-Efficient Learning of Deep
    Networks from Decentralized Data" (2017)
    """

    def __init__(
        self,
        initial_model: torch.nn.Module,
        min_clients: int = 2,
        aggregation_strategy: str = "weighted_average"
    ):
        """
        Initialize the FedAvg aggregator.

        Args:
            initial_model: The initial global model
            min_clients: Minimum number of clients required for aggregation
            aggregation_strategy: Strategy for aggregating updates
                ("weighted_average" or "simple_average")
        """
        self.global_model = copy.deepcopy(initial_model)
        self.min_clients = min_clients
        self.aggregation_strategy = aggregation_strategy
        self.current_round = 0
        self.client_updates: Dict[str, Dict] = {}

    def get_global_weights(self) -> Dict[str, torch.Tensor]:
        """
        Get current global model weights.

        Returns:
            Dictionary of model parameter tensors
        """
        return {
            name: param.data.clone()
            for name, param in self.global_model.named_parameters()
        }

    def receive_update(
        self,
        client_id: str,
        weights: Dict[str, torch.Tensor],
        num_samples: int,
        metrics: Optional[Dict] = None
    ) -> None:
        """
        Receive a model update from a client.

        Args:
            client_id: Unique identifier for the client
            weights: Client's model weights after local training
            num_samples: Number of samples used for local training
            metrics: Optional training metrics (loss, accuracy, etc.)
        """
        self.client_updates[client_id] = {
            'weights': weights,
            'num_samples': num_samples,
            'metrics': metrics or {}
        }
        logger.info(f"Received update from client {client_id} "
                   f"(samples: {num_samples})")

    def can_aggregate(self) -> bool:
        """
        Check if enough clients have submitted updates.

        Returns:
            True if minimum client threshold is met
        """
        return len(self.client_updates) >= self.min_clients

    def aggregate(self) -> Tuple[Dict[str, torch.Tensor], Dict]:
        """
        Aggregate client updates using federated averaging.

        Returns:
            Tuple of (aggregated_weights, aggregation_metrics)

        Raises:
            ValueError: If not enough clients have submitted updates
        """
        if not self.can_aggregate():
            raise ValueError(
                f"Not enough clients: {len(self.client_updates)} < {self.min_clients}"
            )

        if self.aggregation_strategy == "weighted_average":
            aggregated_weights = self._weighted_average()
        else:
            aggregated_weights = self._simple_average()

        self._update_global_model(aggregated_weights)

        metrics = self._compute_aggregation_metrics()

        self.current_round += 1
        self.client_updates.clear()

        logger.info(f"Completed aggregation round {self.current_round}")

        return aggregated_weights, metrics

    def _weighted_average(self) -> Dict[str, torch.Tensor]:
        """
        Compute weighted average of client weights.

        Weights are proportional to the number of training samples.
        """
        total_samples = sum(
            update['num_samples'] for update in self.client_updates.values()
        )

        aggregated_weights = {}
        sample_weights = self.client_updates[list(self.client_updates.keys())[0]]['weights']

        for param_name in sample_weights.keys():
            weighted_sum = torch.zeros_like(sample_weights[param_name])

            for client_id, update in self.client_updates.items():
                weight = update['num_samples'] / total_samples
                weighted_sum += weight * update['weights'][param_name]

            aggregated_weights[param_name] = weighted_sum

        return aggregated_weights

    def _simple_average(self) -> Dict[str, torch.Tensor]:
        """
        Compute simple average of client weights.

        All clients contribute equally regardless of sample count.
        """
        num_clients = len(self.client_updates)
        aggregated_weights = {}
        sample_weights = self.client_updates[list(self.client_updates.keys())[0]]['weights']

        for param_name in sample_weights.keys():
            param_sum = torch.zeros_like(sample_weights[param_name])

            for update in self.client_updates.values():
                param_sum += update['weights'][param_name]

            aggregated_weights[param_name] = param_sum / num_clients

        return aggregated_weights

    def _update_global_model(self, weights: Dict[str, torch.Tensor]) -> None:
        """Update the global model with aggregated weights."""
        state_dict = self.global_model.state_dict()
        for name, param in weights.items():
            if name in state_dict:
                state_dict[name] = param
        self.global_model.load_state_dict(state_dict)

    def _compute_aggregation_metrics(self) -> Dict:
        """Compute metrics about the aggregation process."""
        client_metrics = []
        total_samples = 0

        for client_id, update in self.client_updates.items():
            total_samples += update['num_samples']
            if update['metrics']:
                client_metrics.append(update['metrics'])

        avg_loss = None
        avg_accuracy = None

        if client_metrics:
            losses = [m.get('loss', 0) for m in client_metrics if 'loss' in m]
            accuracies = [m.get('accuracy', 0) for m in client_metrics if 'accuracy' in m]

            if losses:
                avg_loss = sum(losses) / len(losses)
            if accuracies:
                avg_accuracy = sum(accuracies) / len(accuracies)

        return {
            'round': self.current_round,
            'num_clients': len(self.client_updates),
            'total_samples': total_samples,
            'avg_loss': avg_loss,
            'avg_accuracy': avg_accuracy
        }

    def get_round_info(self) -> Dict:
        """Get information about the current round."""
        return {
            'current_round': self.current_round,
            'pending_updates': len(self.client_updates),
            'min_clients': self.min_clients,
            'can_aggregate': self.can_aggregate()
        }
