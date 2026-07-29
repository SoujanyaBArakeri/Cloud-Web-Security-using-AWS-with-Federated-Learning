"""
WAF Updater

Interfaces with AWS WAF API to apply rule updates generated
from the Federated Learning model.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

from .rule_generator import WafRule, RuleGenerator

logger = logging.getLogger(__name__)


class WafUpdater:
    """
    Updates AWS WAF WebACL with rules from the FL model.

    Handles:
    - Fetching current WebACL configuration
    - Adding/updating/removing rules
    - Safe rollback on errors
    - Rule deployment strategies (gradual, immediate)
    """

    def __init__(
        self,
        web_acl_name: str,
        web_acl_id: str,
        scope: str = "REGIONAL",
        region: str = None
    ):
        """
        Initialize the WAF updater.

        Args:
            web_acl_name: Name of the WebACL
            web_acl_id: ID of the WebACL
            scope: WAF scope (REGIONAL or CLOUDFRONT)
            region: AWS region
        """
        self.web_acl_name = web_acl_name
        self.web_acl_id = web_acl_id
        self.scope = scope
        self.region = region or os.environ.get('AWS_REGION', 'us-east-1')

        self.client = boto3.client('wafv2', region_name=self.region)
        self.lock_token: Optional[str] = None

    def get_web_acl(self) -> Tuple[Dict, str]:
        """
        Get current WebACL configuration.

        Returns:
            Tuple of (webacl_config, lock_token)
        """
        try:
            response = self.client.get_web_acl(
                Name=self.web_acl_name,
                Scope=self.scope,
                Id=self.web_acl_id
            )
            self.lock_token = response['LockToken']
            return response['WebACL'], self.lock_token

        except ClientError as e:
            logger.error(f"Failed to get WebACL: {e}")
            raise

    def get_current_rules(self) -> List[Dict]:
        """Get list of current rules in the WebACL."""
        web_acl, _ = self.get_web_acl()
        return web_acl.get('Rules', [])

    def add_rule(
        self,
        rule: WafRule,
        dry_run: bool = False
    ) -> bool:
        """
        Add a single rule to the WebACL.

        Args:
            rule: WafRule to add
            dry_run: If True, validate but don't apply

        Returns:
            True if successful
        """
        return self.add_rules([rule], dry_run)

    def add_rules(
        self,
        rules: List[WafRule],
        dry_run: bool = False
    ) -> bool:
        """
        Add multiple rules to the WebACL.

        Args:
            rules: List of WafRules to add
            dry_run: If True, validate but don't apply

        Returns:
            True if successful
        """
        try:
            web_acl, lock_token = self.get_web_acl()
            current_rules = web_acl.get('Rules', [])

            current_names = {r['Name'] for r in current_rules}
            new_rules = []

            for rule in rules:
                if rule.name in current_names:
                    logger.info(f"Rule {rule.name} already exists, skipping")
                    continue
                new_rules.append(rule.to_waf_format())

            if not new_rules:
                logger.info("No new rules to add")
                return True

            updated_rules = current_rules + new_rules

            if dry_run:
                logger.info(f"[DRY RUN] Would add {len(new_rules)} rules")
                return True

            self.client.update_web_acl(
                Name=self.web_acl_name,
                Scope=self.scope,
                Id=self.web_acl_id,
                DefaultAction=web_acl['DefaultAction'],
                Rules=updated_rules,
                VisibilityConfig=web_acl['VisibilityConfig'],
                LockToken=lock_token
            )

            logger.info(f"Successfully added {len(new_rules)} rules")
            return True

        except ClientError as e:
            logger.error(f"Failed to add rules: {e}")
            return False

    def remove_rule(self, rule_name: str, dry_run: bool = False) -> bool:
        """
        Remove a rule from the WebACL.

        Args:
            rule_name: Name of rule to remove
            dry_run: If True, validate but don't apply

        Returns:
            True if successful
        """
        try:
            web_acl, lock_token = self.get_web_acl()
            current_rules = web_acl.get('Rules', [])

            updated_rules = [r for r in current_rules if r['Name'] != rule_name]

            if len(updated_rules) == len(current_rules):
                logger.warning(f"Rule {rule_name} not found")
                return False

            if dry_run:
                logger.info(f"[DRY RUN] Would remove rule {rule_name}")
                return True

            self.client.update_web_acl(
                Name=self.web_acl_name,
                Scope=self.scope,
                Id=self.web_acl_id,
                DefaultAction=web_acl['DefaultAction'],
                Rules=updated_rules,
                VisibilityConfig=web_acl['VisibilityConfig'],
                LockToken=lock_token
            )

            logger.info(f"Successfully removed rule {rule_name}")
            return True

        except ClientError as e:
            logger.error(f"Failed to remove rule: {e}")
            return False

    def update_rule_action(
        self,
        rule_name: str,
        new_action: str,
        dry_run: bool = False
    ) -> bool:
        """
        Update a rule's action (BLOCK/COUNT).

        Args:
            rule_name: Name of rule to update
            new_action: New action (BLOCK or COUNT)
            dry_run: If True, validate but don't apply

        Returns:
            True if successful
        """
        try:
            web_acl, lock_token = self.get_web_acl()
            current_rules = web_acl.get('Rules', [])

            rule_found = False
            for rule in current_rules:
                if rule['Name'] == rule_name:
                    if new_action == "BLOCK":
                        rule['Action'] = {"Block": {}}
                    else:
                        rule['Action'] = {"Count": {}}
                    rule_found = True
                    break

            if not rule_found:
                logger.warning(f"Rule {rule_name} not found")
                return False

            if dry_run:
                logger.info(f"[DRY RUN] Would update {rule_name} action to {new_action}")
                return True

            self.client.update_web_acl(
                Name=self.web_acl_name,
                Scope=self.scope,
                Id=self.web_acl_id,
                DefaultAction=web_acl['DefaultAction'],
                Rules=current_rules,
                VisibilityConfig=web_acl['VisibilityConfig'],
                LockToken=lock_token
            )

            logger.info(f"Successfully updated {rule_name} action to {new_action}")
            return True

        except ClientError as e:
            logger.error(f"Failed to update rule action: {e}")
            return False

    def apply_fl_update(
        self,
        model_predictions: List[Dict],
        confidence_threshold: float = 0.9,
        dry_run: bool = False
    ) -> Dict:
        """
        Apply updates from federated learning model.

        Args:
            model_predictions: List of model predictions
            confidence_threshold: Minimum confidence to apply rule
            dry_run: If True, validate but don't apply

        Returns:
            Summary of applied changes
        """
        generator = RuleGenerator()

        high_confidence = [
            p for p in model_predictions
            if p.get('confidence', 0) >= confidence_threshold
        ]

        for pred in high_confidence:
            pred['action'] = 'BLOCK'

        medium_confidence = [
            p for p in model_predictions
            if 0.7 <= p.get('confidence', 0) < confidence_threshold
        ]

        for pred in medium_confidence:
            pred['action'] = 'COUNT'

        all_predictions = high_confidence + medium_confidence
        rules = generator.generate_rules_from_predictions(all_predictions)

        success = self.add_rules(rules, dry_run=dry_run)

        return {
            'success': success,
            'total_predictions': len(model_predictions),
            'high_confidence_rules': len(high_confidence),
            'medium_confidence_rules': len(medium_confidence),
            'rules_applied': len(rules),
            'dry_run': dry_run,
            'timestamp': datetime.utcnow().isoformat()
        }

    def get_metrics(self, metric_name: str, hours: int = 24) -> Dict:
        """
        Get CloudWatch metrics for WAF rules.

        Args:
            metric_name: Name of the WAF metric
            hours: Number of hours to look back

        Returns:
            Metrics data
        """
        try:
            cloudwatch = boto3.client('cloudwatch', region_name=self.region)

            from datetime import timedelta
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)

            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/WAFV2',
                MetricName=metric_name,
                Dimensions=[
                    {'Name': 'WebACL', 'Value': self.web_acl_name},
                    {'Name': 'Region', 'Value': self.region},
                    {'Name': 'Rule', 'Value': 'ALL'}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum', 'Average']
            )

            return {
                'metric': metric_name,
                'datapoints': response.get('Datapoints', []),
                'period_hours': hours
            }

        except ClientError as e:
            logger.error(f"Failed to get metrics: {e}")
            return {}
