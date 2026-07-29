"""
Federated Learning Aggregation Server

HTTP server that coordinates federated learning across multiple
client organizations. Handles model distribution, update collection,
and aggregation orchestration.
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Optional
from flask import Flask, request, jsonify
import torch
import io
import base64

from ..models.threat_detection_model import ThreatDetectionModel
from .federated_averaging import FederatedAveraging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AggregationServer:
    """
    Central server for federated learning coordination.

    Responsibilities:
    - Distribute global model to clients
    - Collect model updates from clients
    - Aggregate updates using FedAvg
    - Track training progress and metrics
    """

    def __init__(
        self,
        num_rounds: int = 10,
        min_clients: int = 2,
        model_save_path: str = "models"
    ):
        """
        Initialize the aggregation server.

        Args:
            num_rounds: Total number of federated learning rounds
            min_clients: Minimum clients required per round
            model_save_path: Directory to save model checkpoints
        """
        self.num_rounds = num_rounds
        self.min_clients = min_clients
        self.model_save_path = model_save_path
        os.makedirs(model_save_path, exist_ok=True)

        self.global_model = ThreatDetectionModel()
        self.fed_avg = FederatedAveraging(
            self.global_model,
            min_clients=min_clients
        )

        self.registered_clients: Dict[str, Dict] = {}
        self.round_history: list = []
        self.is_training = False
        self.current_round = 0

        self.app = self._create_app()

    def _create_app(self) -> Flask:
        """Create Flask application with API endpoints."""
        app = Flask(__name__)

        @app.route('/health', methods=['GET'])
        def health():
            return jsonify({
                'status': 'healthy',
                'current_round': self.current_round,
                'registered_clients': len(self.registered_clients),
                'is_training': self.is_training
            })

        @app.route('/register', methods=['POST'])
        def register_client():
            data = request.get_json()
            client_id = data.get('client_id')
            if not client_id:
                return jsonify({'error': 'client_id required'}), 400

            self.registered_clients[client_id] = {
                'registered_at': datetime.utcnow().isoformat(),
                'last_seen': datetime.utcnow().isoformat(),
                'rounds_participated': 0
            }

            logger.info(f"Client registered: {client_id}")
            return jsonify({
                'success': True,
                'client_id': client_id,
                'current_round': self.current_round
            })

        @app.route('/model', methods=['GET'])
        def get_model():
            """Distribute current global model to clients."""
            buffer = io.BytesIO()
            torch.save(self.global_model.state_dict(), buffer)
            model_bytes = buffer.getvalue()
            model_b64 = base64.b64encode(model_bytes).decode('utf-8')

            return jsonify({
                'model': model_b64,
                'round': self.current_round,
                'version': self.global_model.version,
                'checksum': hashlib.sha256(model_bytes).hexdigest()[:16]
            })

        @app.route('/update', methods=['POST'])
        def receive_update():
            """Receive model update from a client."""
            data = request.get_json()

            client_id = data.get('client_id')
            if not client_id or client_id not in self.registered_clients:
                return jsonify({'error': 'Invalid or unregistered client'}), 400

            try:
                weights_b64 = data.get('weights')
                weights_bytes = base64.b64decode(weights_b64)
                buffer = io.BytesIO(weights_bytes)
                weights = torch.load(buffer, weights_only=True)

                num_samples = data.get('num_samples', 0)
                metrics = data.get('metrics', {})

                self.fed_avg.receive_update(
                    client_id=client_id,
                    weights=weights,
                    num_samples=num_samples,
                    metrics=metrics
                )

                self.registered_clients[client_id]['last_seen'] = datetime.utcnow().isoformat()
                self.registered_clients[client_id]['rounds_participated'] += 1

                if self.fed_avg.can_aggregate():
                    self._perform_aggregation()

                return jsonify({
                    'success': True,
                    'round': self.current_round,
                    'aggregation_ready': self.fed_avg.can_aggregate()
                })

            except Exception as e:
                logger.error(f"Error processing update from {client_id}: {e}")
                return jsonify({'error': str(e)}), 500

        @app.route('/status', methods=['GET'])
        def get_status():
            """Get current training status."""
            return jsonify({
                'current_round': self.current_round,
                'total_rounds': self.num_rounds,
                'registered_clients': len(self.registered_clients),
                'pending_updates': len(self.fed_avg.client_updates),
                'min_clients': self.min_clients,
                'is_training': self.is_training,
                'round_history': self.round_history[-10:]
            })

        @app.route('/start', methods=['POST'])
        def start_training():
            """Start the federated learning process."""
            if self.is_training:
                return jsonify({'error': 'Training already in progress'}), 400

            if len(self.registered_clients) < self.min_clients:
                return jsonify({
                    'error': f'Not enough clients: {len(self.registered_clients)} < {self.min_clients}'
                }), 400

            self.is_training = True
            self.current_round = 0
            logger.info("Federated learning started")

            return jsonify({
                'success': True,
                'message': 'Training started',
                'num_rounds': self.num_rounds
            })

        @app.route('/stop', methods=['POST'])
        def stop_training():
            """Stop the federated learning process."""
            self.is_training = False
            self._save_model('final')
            logger.info("Federated learning stopped")

            return jsonify({
                'success': True,
                'message': 'Training stopped',
                'final_round': self.current_round
            })

        @app.route('/metrics', methods=['GET'])
        def get_metrics():
            """Get training metrics."""
            return jsonify({
                'round_history': self.round_history,
                'current_round': self.current_round,
                'model_params': self.global_model.count_parameters()
            })

        return app

    def _perform_aggregation(self) -> None:
        """Perform model aggregation and advance to next round."""
        try:
            _, metrics = self.fed_avg.aggregate()

            self.round_history.append({
                'round': self.current_round,
                'timestamp': datetime.utcnow().isoformat(),
                'metrics': metrics
            })

            self._save_model(f'round_{self.current_round}')

            self.current_round += 1

            if self.current_round >= self.num_rounds:
                self.is_training = False
                self._save_model('final')
                logger.info("Training completed!")

            logger.info(f"Aggregation complete. Moving to round {self.current_round}")

        except Exception as e:
            logger.error(f"Aggregation failed: {e}")

    def _save_model(self, tag: str) -> str:
        """Save model checkpoint."""
        path = os.path.join(self.model_save_path, f'model_{tag}.pt')
        self.global_model.save(path)
        logger.info(f"Model saved: {path}")
        return path

    def run(self, host: str = '0.0.0.0', port: int = 8080) -> None:
        """Run the aggregation server."""
        logger.info(f"Starting aggregation server on {host}:{port}")
        self.app.run(host=host, port=port, debug=False)


def main():
    """Main entry point for the aggregation server."""
    num_rounds = int(os.environ.get('FL_NUM_ROUNDS', 10))
    min_clients = int(os.environ.get('FL_MIN_CLIENTS', 2))
    model_path = os.environ.get('MODEL_SAVE_PATH', 'models')
    host = os.environ.get('FL_SERVER_HOST', '0.0.0.0')
    port = int(os.environ.get('FL_SERVER_PORT', 8080))

    server = AggregationServer(
        num_rounds=num_rounds,
        min_clients=min_clients,
        model_save_path=model_path
    )
    server.run(host=host, port=port)


if __name__ == '__main__':
    main()
