"""
Differential Privacy for Federated Learning

Implements differential privacy mechanisms to protect individual
data points during federated learning by adding calibrated noise
to model gradients.
"""

import torch
from typing import Dict, Tuple, Optional
import math
import logging

logger = logging.getLogger(__name__)


class DifferentialPrivacy:
    """
    Differential Privacy implementation for gradient protection.

    Uses the Gaussian mechanism to add noise to gradients before
    sharing them with the aggregation server, providing (epsilon, delta)
    differential privacy guarantees.
    """

    def __init__(
        self,
        epsilon: float = 1.0,
        delta: float = 1e-5,
        max_grad_norm: float = 1.0,
        noise_multiplier: Optional[float] = None
    ):
        """
        Initialize differential privacy settings.

        Args:
            epsilon: Privacy budget (lower = more private)
            delta: Probability of privacy breach
            max_grad_norm: Maximum gradient norm for clipping
            noise_multiplier: Manual noise multiplier (overrides epsilon/delta calculation)
        """
        self.epsilon = epsilon
        self.delta = delta
        self.max_grad_norm = max_grad_norm

        if noise_multiplier is not None:
            self.noise_multiplier = noise_multiplier
        else:
            self.noise_multiplier = self._compute_noise_multiplier()

        logger.info(
            f"DP initialized: epsilon={epsilon}, delta={delta}, "
            f"noise_multiplier={self.noise_multiplier:.4f}"
        )

    def _compute_noise_multiplier(self) -> float:
        """
        Compute noise multiplier from privacy parameters.

        Uses the simple composition theorem. For tighter bounds,
        consider using Renyi DP or advanced composition.
        """
        return math.sqrt(2 * math.log(1.25 / self.delta)) / self.epsilon

    def clip_gradients(
        self,
        gradients: Dict[str, torch.Tensor]
    ) -> Tuple[Dict[str, torch.Tensor], float]:
        """
        Clip gradients to bound sensitivity.

        Args:
            gradients: Dictionary of gradient tensors

        Returns:
            Tuple of (clipped_gradients, actual_norm)
        """
        all_grads = torch.cat([g.flatten() for g in gradients.values()])
        total_norm = torch.norm(all_grads, p=2)

        clip_coef = min(1.0, self.max_grad_norm / (total_norm + 1e-8))

        clipped = {
            name: grad * clip_coef
            for name, grad in gradients.items()
        }

        return clipped, total_norm.item()

    def add_noise(
        self,
        gradients: Dict[str, torch.Tensor],
        num_samples: int
    ) -> Dict[str, torch.Tensor]:
        """
        Add Gaussian noise to gradients.

        Args:
            gradients: Dictionary of gradient tensors
            num_samples: Number of samples in the local dataset

        Returns:
            Noisy gradients
        """
        std = self.noise_multiplier * self.max_grad_norm / num_samples

        noisy_gradients = {}
        for name, grad in gradients.items():
            noise = torch.normal(
                mean=0,
                std=std,
                size=grad.shape,
                device=grad.device
            )
            noisy_gradients[name] = grad + noise

        return noisy_gradients

    def privatize_gradients(
        self,
        gradients: Dict[str, torch.Tensor],
        num_samples: int
    ) -> Tuple[Dict[str, torch.Tensor], Dict]:
        """
        Apply differential privacy to gradients.

        This is the main function to call for privatizing gradients.
        It clips and then adds noise.

        Args:
            gradients: Dictionary of gradient tensors
            num_samples: Number of samples in the local dataset

        Returns:
            Tuple of (private_gradients, privacy_stats)
        """
        clipped_grads, original_norm = self.clip_gradients(gradients)

        private_grads = self.add_noise(clipped_grads, num_samples)

        stats = {
            'original_norm': original_norm,
            'clip_norm': self.max_grad_norm,
            'was_clipped': original_norm > self.max_grad_norm,
            'noise_std': self.noise_multiplier * self.max_grad_norm / num_samples,
            'epsilon': self.epsilon,
            'delta': self.delta
        }

        return private_grads, stats

    def compute_privacy_spent(
        self,
        num_rounds: int,
        sample_rate: float
    ) -> Tuple[float, float]:
        """
        Compute the total privacy spent after multiple rounds.

        Uses simple composition. For tighter bounds, use RDP accounting.

        Args:
            num_rounds: Number of training rounds
            sample_rate: Fraction of data sampled per round

        Returns:
            Tuple of (total_epsilon, delta)
        """
        per_round_epsilon = self.epsilon * sample_rate
        total_epsilon = per_round_epsilon * math.sqrt(num_rounds)

        return total_epsilon, self.delta


class GradientAccumulator:
    """
    Accumulates gradients with differential privacy.

    Useful for micro-batching to reduce noise variance.
    """

    def __init__(self, dp: DifferentialPrivacy):
        """
        Initialize the accumulator.

        Args:
            dp: DifferentialPrivacy instance
        """
        self.dp = dp
        self.accumulated_grads: Dict[str, torch.Tensor] = {}
        self.num_accumulated = 0

    def add(self, gradients: Dict[str, torch.Tensor]) -> None:
        """Add gradients to the accumulator."""
        for name, grad in gradients.items():
            if name in self.accumulated_grads:
                self.accumulated_grads[name] += grad
            else:
                self.accumulated_grads[name] = grad.clone()
        self.num_accumulated += 1

    def get_private_gradients(self, num_samples: int) -> Dict[str, torch.Tensor]:
        """
        Get averaged and privatized gradients.

        Returns:
            Private gradients
        """
        averaged = {
            name: grad / self.num_accumulated
            for name, grad in self.accumulated_grads.items()
        }

        private_grads, _ = self.dp.privatize_gradients(averaged, num_samples)

        self.accumulated_grads = {}
        self.num_accumulated = 0

        return private_grads
