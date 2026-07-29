"""
Unit tests for the Threat Detection Model
"""

import pytest
import torch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from federated_learning.models.threat_detection_model import (
    ThreatDetectionModel,
    ThreatDetectionModelLight,
    ThreatDetectionModelLarge
)


class TestThreatDetectionModel:
    """Tests for ThreatDetectionModel."""

    def test_model_initialization(self):
        """Test model initializes correctly."""
        model = ThreatDetectionModel()
        assert model is not None
        assert model.input_dim == 14
        assert model.NUM_CLASSES == 5

    def test_forward_pass(self):
        """Test forward pass produces correct output shape."""
        model = ThreatDetectionModel()
        batch_size = 32
        x = torch.randn(batch_size, 14)

        output = model(x)

        assert output.shape == (batch_size, 5)

    def test_predict(self):
        """Test prediction returns classes and confidences."""
        model = ThreatDetectionModel()
        x = torch.randn(10, 14)

        classes, confidences = model.predict(x)

        assert classes.shape == (10,)
        assert confidences.shape == (10,)
        assert torch.all(classes >= 0) and torch.all(classes < 5)
        assert torch.all(confidences >= 0) and torch.all(confidences <= 1)

    def test_predict_proba(self):
        """Test probability predictions sum to 1."""
        model = ThreatDetectionModel()
        x = torch.randn(10, 14)

        probs = model.predict_proba(x)

        assert probs.shape == (10, 5)
        sums = probs.sum(dim=1)
        assert torch.allclose(sums, torch.ones(10), atol=1e-5)

    def test_get_weights(self):
        """Test getting model weights."""
        model = ThreatDetectionModel()
        weights = model.get_weights()

        assert isinstance(weights, dict)
        assert len(weights) > 0

    def test_set_weights(self):
        """Test setting model weights."""
        model1 = ThreatDetectionModel()
        model2 = ThreatDetectionModel()

        weights1 = model1.get_weights()
        model2.set_weights(weights1)
        weights2 = model2.get_weights()

        for name in weights1:
            assert torch.equal(weights1[name], weights2[name])

    def test_clone(self):
        """Test model cloning."""
        model1 = ThreatDetectionModel()
        model2 = model1.clone()

        assert model1 is not model2

        weights1 = model1.get_weights()
        weights2 = model2.get_weights()
        for name in weights1:
            assert torch.equal(weights1[name], weights2[name])

    def test_count_parameters(self):
        """Test parameter counting."""
        model = ThreatDetectionModel()
        params = model.count_parameters()

        assert params > 0
        assert isinstance(params, int)

    def test_get_threat_name(self):
        """Test threat name lookup."""
        model = ThreatDetectionModel()

        assert model.get_threat_name(0) == "benign"
        assert model.get_threat_name(1) == "sql_injection"
        assert model.get_threat_name(2) == "xss"
        assert model.get_threat_name(3) == "ddos"
        assert model.get_threat_name(4) == "bot"
        assert model.get_threat_name(5) == "unknown"

    def test_feature_names(self):
        """Test feature name list."""
        names = ThreatDetectionModel.get_feature_names()

        assert len(names) == 14
        assert "sql_keyword_count" in names
        assert "xss_keyword_count" in names


class TestModelVariants:
    """Tests for model variants."""

    def test_light_model(self):
        """Test lightweight model variant."""
        model = ThreatDetectionModelLight()
        x = torch.randn(10, 14)

        output = model(x)

        assert output.shape == (10, 5)
        assert model.count_parameters() < ThreatDetectionModel().count_parameters()

    def test_large_model(self):
        """Test large model variant."""
        model = ThreatDetectionModelLarge()
        x = torch.randn(10, 14)

        output = model(x)

        assert output.shape == (10, 5)
        assert model.count_parameters() > ThreatDetectionModel().count_parameters()


class TestModelTraining:
    """Tests for model training functionality."""

    def test_gradient_computation(self):
        """Test gradients are computed during training."""
        model = ThreatDetectionModel()
        model.train()

        x = torch.randn(32, 14)
        y = torch.randint(0, 5, (32,))

        output = model(x)
        loss = torch.nn.functional.cross_entropy(output, y)
        loss.backward()

        gradients = model.get_gradients()
        assert len(gradients) > 0

    def test_training_step(self):
        """Test a complete training step."""
        model = ThreatDetectionModel()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        criterion = torch.nn.CrossEntropyLoss()

        x = torch.randn(32, 14)
        y = torch.randint(0, 5, (32,))

        model.train()
        optimizer.zero_grad()
        output = model(x)
        loss = criterion(output, y)
        loss.backward()
        optimizer.step()

        assert loss.item() >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
