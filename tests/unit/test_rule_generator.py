"""
Unit tests for the WAF Rule Generator
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from waf_integration.rule_generator import RuleGenerator, WafRule


class TestWafRule:
    """Tests for WafRule dataclass."""

    def test_rule_creation(self):
        """Test WafRule creation."""
        rule = WafRule(
            name="test_rule",
            description="Test rule",
            priority=100,
            action="BLOCK",
            rule_type="ByteMatch",
            statement={"test": "statement"},
            created_at="2024-01-01T00:00:00",
            confidence=0.95
        )

        assert rule.name == "test_rule"
        assert rule.action == "BLOCK"
        assert rule.confidence == 0.95

    def test_to_waf_format(self):
        """Test conversion to WAF API format."""
        rule = WafRule(
            name="test_rule",
            description="Test",
            priority=100,
            action="BLOCK",
            rule_type="ByteMatch",
            statement={"ByteMatchStatement": {}},
            created_at="2024-01-01T00:00:00",
            confidence=0.95
        )

        waf_format = rule.to_waf_format()

        assert waf_format["Name"] == "test_rule"
        assert waf_format["Priority"] == 100
        assert "Block" in waf_format["Action"]
        assert waf_format["VisibilityConfig"]["CloudWatchMetricsEnabled"] is True


class TestRuleGenerator:
    """Tests for RuleGenerator."""

    def test_initialization(self):
        """Test generator initialization."""
        generator = RuleGenerator(base_priority=50)

        assert generator.base_priority == 50
        assert len(generator.generated_rules) == 0

    def test_generate_sql_injection_rule(self):
        """Test SQL injection rule generation."""
        generator = RuleGenerator()

        rule = generator.generate_rule_from_pattern(
            pattern="SELECT * FROM users",
            threat_type="sql_injection",
            confidence=0.95,
            action="BLOCK"
        )

        assert rule is not None
        assert "sql_injection" in rule.name
        assert rule.action == "BLOCK"
        assert rule.confidence == 0.95

    def test_generate_xss_rule(self):
        """Test XSS rule generation."""
        generator = RuleGenerator()

        rule = generator.generate_rule_from_pattern(
            pattern="<script>alert(1)</script>",
            threat_type="xss",
            confidence=0.92,
            action="BLOCK"
        )

        assert rule is not None
        assert "xss" in rule.name

    def test_low_confidence_rejected(self):
        """Test that low confidence patterns are rejected."""
        generator = RuleGenerator()

        rule = generator.generate_rule_from_pattern(
            pattern="test",
            threat_type="sql_injection",
            confidence=0.5,
            action="BLOCK"
        )

        assert rule is None

    def test_medium_confidence_count_only(self):
        """Test that medium confidence patterns use COUNT action."""
        generator = RuleGenerator()

        rule = generator.generate_rule_from_pattern(
            pattern="SELECT",
            threat_type="sql_injection",
            confidence=0.85,
            action="BLOCK"
        )

        assert rule is not None
        assert rule.action == "COUNT"

    def test_generate_from_predictions(self):
        """Test generating multiple rules from predictions."""
        generator = RuleGenerator()

        predictions = [
            {"pattern": "UNION SELECT", "threat_type": "sql_injection", "confidence": 0.95},
            {"pattern": "<script>", "threat_type": "xss", "confidence": 0.92},
            {"pattern": "low_conf", "threat_type": "bot", "confidence": 0.5},
        ]

        rules = generator.generate_rules_from_predictions(predictions)

        assert len(rules) == 2

    def test_rate_limit_rule(self):
        """Test rate limiting rule generation."""
        generator = RuleGenerator()

        rule = generator.generate_rate_limit_rule(
            limit=1000,
            window_seconds=300,
            aggregate_key="IP"
        )

        assert rule is not None
        assert rule.rule_type == "RateBased"
        assert rule.action == "BLOCK"
        assert rule.confidence == 1.0

    def test_unique_rule_names(self):
        """Test that rule names are unique."""
        generator = RuleGenerator()

        rule1 = generator.generate_rule_from_pattern(
            pattern="test1",
            threat_type="sql_injection",
            confidence=0.95
        )
        rule2 = generator.generate_rule_from_pattern(
            pattern="test2",
            threat_type="sql_injection",
            confidence=0.95
        )

        assert rule1.name != rule2.name

    def test_get_summary(self):
        """Test summary generation."""
        generator = RuleGenerator()

        generator.generate_rule_from_pattern("SELECT", "sql_injection", 0.95, "BLOCK")
        generator.generate_rule_from_pattern("<script>", "xss", 0.85, "COUNT")

        summary = generator.get_summary()

        assert summary["total_rules"] == 2
        assert "by_action" in summary
        assert "avg_confidence" in summary


class TestPatternValidation:
    """Tests for pattern validation."""

    def test_short_pattern_rejected(self):
        """Test that very short patterns are rejected."""
        generator = RuleGenerator()

        rule = generator.generate_rule_from_pattern(
            pattern="ab",
            threat_type="sql_injection",
            confidence=0.95
        )

        assert rule is None

    def test_long_pattern_rejected(self):
        """Test that very long patterns are rejected."""
        generator = RuleGenerator()

        rule = generator.generate_rule_from_pattern(
            pattern="x" * 250,
            threat_type="sql_injection",
            confidence=0.95
        )

        assert rule is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
