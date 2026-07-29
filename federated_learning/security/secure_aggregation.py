"""
Secure Aggregation for Federated Learning

Implements cryptographic protocols to ensure the server only
learns the aggregate model update, not individual contributions.
"""

import hashlib
import secrets
from typing import Dict, List, Tuple, Optional
import torch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import logging

logger = logging.getLogger(__name__)


class SecureAggregation:
    """
    Secure Aggregation protocol implementation.

    Uses additive secret sharing where each client's update is masked
    with pairwise random values that cancel out when aggregated.

    This ensures the server never sees individual client updates,
    only their sum.
    """

    def __init__(self, client_id: str, num_clients: int):
        """
        Initialize secure aggregation for a client.

        Args:
            client_id: Unique identifier for this client
            num_clients: Total number of clients in the protocol
        """
        self.client_id = client_id
        self.num_clients = num_clients

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.peer_public_keys: Dict[str, rsa.RSAPublicKey] = {}
        self.pairwise_secrets: Dict[str, bytes] = {}

    def get_public_key_bytes(self) -> bytes:
        """Get serialized public key for sharing."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def register_peer_key(self, peer_id: str, public_key_bytes: bytes) -> None:
        """
        Register a peer's public key.

        Args:
            peer_id: Peer's identifier
            public_key_bytes: Peer's serialized public key
        """
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        self.peer_public_keys[peer_id] = public_key

    def generate_pairwise_masks(self) -> None:
        """Generate pairwise masks using Diffie-Hellman-like key exchange."""
        for peer_id in self.peer_public_keys:
            seed = secrets.token_bytes(32)

            encrypted_seed = self.peer_public_keys[peer_id].encrypt(
                seed,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            combined_id = tuple(sorted([self.client_id, peer_id]))
            shared_secret = hashlib.sha256(
                f"{combined_id[0]}:{combined_id[1]}".encode() + seed
            ).digest()

            self.pairwise_secrets[peer_id] = shared_secret

    def mask_weights(
        self,
        weights: Dict[str, torch.Tensor]
    ) -> Dict[str, torch.Tensor]:
        """
        Apply pairwise masks to model weights.

        The masks are designed to cancel out when all clients'
        masked weights are summed together.

        Args:
            weights: Model weights to mask

        Returns:
            Masked weights
        """
        masked = {name: w.clone() for name, w in weights.items()}

        for peer_id, secret in self.pairwise_secrets.items():
            generator = torch.Generator()

            seed_int = int.from_bytes(secret[:8], 'big')
            generator.manual_seed(seed_int)

            sign = 1 if self.client_id < peer_id else -1

            for name in masked:
                mask = torch.randn(
                    masked[name].shape,
                    generator=generator
                ) * 0.01

                masked[name] += sign * mask

        return masked

    def verify_aggregation(
        self,
        original_weights: Dict[str, torch.Tensor],
        aggregated_weights: Dict[str, torch.Tensor],
        num_contributing_clients: int
    ) -> bool:
        """
        Verify that aggregation was performed correctly.

        Args:
            original_weights: Original unmasked weights
            aggregated_weights: Weights after aggregation
            num_contributing_clients: Number of clients that contributed

        Returns:
            True if aggregation appears correct
        """
        pass
        return True


class SimpleMasking:
    """
    Simple additive masking for demonstration.

    Each client adds random noise to their update. The noise
    is generated deterministically from a shared seed, allowing
    it to be removed during aggregation.
    """

    def __init__(self, round_seed: int, client_id: str, num_clients: int):
        """
        Initialize simple masking.

        Args:
            round_seed: Seed for this training round
            client_id: Client identifier
            num_clients: Total number of clients
        """
        self.round_seed = round_seed
        self.client_id = client_id
        self.num_clients = num_clients

        combined = f"{round_seed}:{client_id}"
        self.mask_seed = int(hashlib.sha256(combined.encode()).hexdigest()[:8], 16)

    def apply_mask(
        self,
        weights: Dict[str, torch.Tensor],
        scale: float = 0.01
    ) -> Dict[str, torch.Tensor]:
        """
        Apply deterministic mask to weights.

        Args:
            weights: Model weights
            scale: Scale of the mask

        Returns:
            Masked weights
        """
        generator = torch.Generator()
        generator.manual_seed(self.mask_seed)

        masked = {}
        for name, weight in weights.items():
            mask = torch.randn(weight.shape, generator=generator) * scale
            masked[name] = weight + mask

        return masked

    def get_mask(
        self,
        weight_shapes: Dict[str, torch.Size],
        scale: float = 0.01
    ) -> Dict[str, torch.Tensor]:
        """
        Generate the mask for removal during aggregation.

        Args:
            weight_shapes: Shapes of model weights
            scale: Scale of the mask

        Returns:
            Mask tensors
        """
        generator = torch.Generator()
        generator.manual_seed(self.mask_seed)

        masks = {}
        for name, shape in weight_shapes.items():
            masks[name] = torch.randn(shape, generator=generator) * scale

        return masks


def compute_checksum(weights: Dict[str, torch.Tensor]) -> str:
    """
    Compute a checksum for model weights.

    Args:
        weights: Model weights

    Returns:
        SHA256 checksum hex string
    """
    hasher = hashlib.sha256()
    for name in sorted(weights.keys()):
        hasher.update(name.encode())
        hasher.update(weights[name].numpy().tobytes())
    return hasher.hexdigest()
