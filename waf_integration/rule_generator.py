"""
WAF Rule Generator

Converts Federated Learning model predictions into AWS WAF rules.
Translates ML insights into actionable security policies.
"""

import json
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class WafRule:
    """Represents an AWS WAF rule."""
    name: str
    description: str
    priority: int
    action: str
    rule_type: str
    statement: Dict
    created_at: str
    confidence: float
    source: str = "federated_learning"

    def to_waf_format(self) -> Dict:
        """Convert to AWS WAF API format."""
        action_config = {"Block": {}} if self.action == "BLOCK" else {"Count": {}}

        return {
            "Name": self.name,
            "Priority": self.priority,
            "Action": action_config,
            "Statement": self.statement,
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": f"FL_{self.name}"
            }
        }


class RuleGenerator:
    """
    Generates AWS WAF rules from ML model predictions.

    Takes threat patterns identified by the federated learning model
    and creates appropriate WAF rules to block or monitor them.
    """

    THREAT_TYPE_PATTERNS = {
        'sql_injection': {
            'keywords': ['select', 'union', 'insert', 'delete', 'drop', 'update', '--', ';'],
            'field': 'body',
            'transform': ['URL_DECODE', 'LOWERCASE']
        },
        'xss': {
            'keywords': ['<script', 'javascript:', 'onerror', 'onload', 'onclick', '<iframe'],
            'field': 'body',
            'transform': ['HTML_ENTITY_DECODE', 'LOWERCASE']
        },
        'path_traversal': {
            'keywords': ['../', '..\\', '/etc/', 'passwd', 'shadow'],
            'field': 'uri_path',
            'transform': ['URL_DECODE', 'LOWERCASE']
        },
        'command_injection': {
            'keywords': ['|', '`', '$', ';', '&&', '||'],
            'field': 'body',
            'transform': ['URL_DECODE']
        }
    }

    def __init__(self, base_priority: int = 100):
        """
        Initialize the rule generator.

        Args:
            base_priority: Starting priority for generated rules
        """
        self.base_priority = base_priority
        self.generated_rules: List[WafRule] = []
        self.rule_counter = 0

    def generate_rule_from_pattern(
        self,
        pattern: str,
        threat_type: str,
        confidence: float,
        action: str = "COUNT"
    ) -> Optional[WafRule]:
        """
        Generate a WAF rule from a detected pattern.

        Args:
            pattern: The attack pattern to block
            threat_type: Type of threat (sql_injection, xss, etc.)
            confidence: Model confidence score (0-1)
            action: WAF action (BLOCK or COUNT)

        Returns:
            Generated WafRule or None if invalid
        """
        if confidence < 0.7:
            logger.warning(f"Low confidence ({confidence}), skipping rule for: {pattern}")
            return None

        if len(pattern) < 3 or len(pattern) > 200:
            logger.warning(f"Invalid pattern length: {len(pattern)}")
            return None

        rule_name = self._generate_rule_name(threat_type, pattern)
        priority = self.base_priority + self.rule_counter

        threat_config = self.THREAT_TYPE_PATTERNS.get(
            threat_type,
            {'field': 'body', 'transform': ['LOWERCASE']}
        )

        statement = self._create_byte_match_statement(
            pattern=pattern,
            field=threat_config['field'],
            transforms=threat_config['transform']
        )

        if confidence < 0.9:
            action = "COUNT"

        rule = WafRule(
            name=rule_name,
            description=f"FL-generated rule for {threat_type}: {pattern[:50]}",
            priority=priority,
            action=action,
            rule_type="ByteMatch",
            statement=statement,
            created_at=datetime.utcnow().isoformat(),
            confidence=confidence
        )

        self.generated_rules.append(rule)
        self.rule_counter += 1

        logger.info(f"Generated rule: {rule_name} ({action})")
        return rule

    def generate_rules_from_predictions(
        self,
        predictions: List[Dict]
    ) -> List[WafRule]:
        """
        Generate multiple rules from model predictions.

        Args:
            predictions: List of prediction dictionaries with
                        'pattern', 'threat_type', 'confidence' keys

        Returns:
            List of generated WafRules
        """
        rules = []
        for pred in predictions:
            rule = self.generate_rule_from_pattern(
                pattern=pred.get('pattern', ''),
                threat_type=pred.get('threat_type', 'unknown'),
                confidence=pred.get('confidence', 0.0),
                action=pred.get('action', 'COUNT')
            )
            if rule:
                rules.append(rule)

        logger.info(f"Generated {len(rules)} rules from {len(predictions)} predictions")
        return rules

    def generate_rate_limit_rule(
        self,
        limit: int = 1000,
        window_seconds: int = 300,
        aggregate_key: str = "IP"
    ) -> WafRule:
        """
        Generate a rate limiting rule for DDoS protection.

        Args:
            limit: Maximum requests per window
            window_seconds: Time window in seconds
            aggregate_key: How to aggregate requests (IP, FORWARDED_IP)

        Returns:
            Rate limiting WafRule
        """
        rule_name = f"FL_RateLimit_{limit}per{window_seconds}s"

        statement = {
            "RateBasedStatement": {
                "Limit": limit,
                "AggregateKeyType": aggregate_key
            }
        }

        rule = WafRule(
            name=rule_name,
            description=f"Rate limit: {limit} requests per {window_seconds}s",
            priority=self.base_priority + self.rule_counter,
            action="BLOCK",
            rule_type="RateBased",
            statement=statement,
            created_at=datetime.utcnow().isoformat(),
            confidence=1.0
        )

        self.generated_rules.append(rule)
        self.rule_counter += 1
        return rule

    def _generate_rule_name(self, threat_type: str, pattern: str) -> str:
        """Generate a unique rule name."""
        pattern_hash = hashlib.sha256(pattern.encode()).hexdigest()[:8]
        return f"FL_{threat_type}_{pattern_hash}"

    def _create_byte_match_statement(
        self,
        pattern: str,
        field: str,
        transforms: List[str]
    ) -> Dict:
        """Create a ByteMatchStatement for WAF."""
        field_match = self._get_field_to_match(field)

        text_transformations = [
            {"Priority": i, "Type": t}
            for i, t in enumerate(transforms)
        ]

        return {
            "ByteMatchStatement": {
                "SearchString": pattern,
                "FieldToMatch": field_match,
                "TextTransformations": text_transformations,
                "PositionalConstraint": "CONTAINS"
            }
        }

    def _get_field_to_match(self, field: str) -> Dict:
        """Get the FieldToMatch configuration."""
        field_mapping = {
            'body': {"Body": {}},
            'uri_path': {"UriPath": {}},
            'query_string': {"QueryString": {}},
            'headers': {"SingleHeader": {"Name": "user-agent"}},
            'all_query_args': {"AllQueryArguments": {}}
        }
        return field_mapping.get(field, {"Body": {}})

    def export_rules(self, filepath: str) -> None:
        """Export generated rules to JSON file."""
        rules_data = [asdict(rule) for rule in self.generated_rules]
        with open(filepath, 'w') as f:
            json.dump(rules_data, f, indent=2)
        logger.info(f"Exported {len(rules_data)} rules to {filepath}")

    def get_summary(self) -> Dict:
        """Get summary of generated rules."""
        action_counts = {}
        type_counts = {}

        for rule in self.generated_rules:
            action_counts[rule.action] = action_counts.get(rule.action, 0) + 1
            type_counts[rule.rule_type] = type_counts.get(rule.rule_type, 0) + 1

        return {
            'total_rules': len(self.generated_rules),
            'by_action': action_counts,
            'by_type': type_counts,
            'avg_confidence': sum(r.confidence for r in self.generated_rules) / max(len(self.generated_rules), 1)
        }
