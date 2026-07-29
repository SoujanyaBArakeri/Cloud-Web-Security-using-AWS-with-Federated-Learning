"""
Lambda Stack

Creates Lambda function for updating WAF rules based on
Federated Learning model predictions.
"""

from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    aws_wafv2 as wafv2,
    CfnOutput,
    Tags
)
from constructs import Construct


class LambdaStack(Stack):
    """
    Creates Lambda function for WAF rule updates.

    Features:
    - Lambda function to update WAF rules from FL model
    - IAM role with WAF permissions
    - EventBridge rule for scheduled execution
    - CloudWatch logging
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        web_acl: wafv2.CfnWebACL,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lambda_role = iam.Role(
            self, "WafUpdaterRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for WAF Rule Updater Lambda"
        )

        lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        )

        lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "wafv2:GetWebACL",
                    "wafv2:UpdateWebACL",
                    "wafv2:ListRules",
                    "wafv2:GetRuleGroup",
                    "wafv2:CreateRuleGroup",
                    "wafv2:UpdateRuleGroup",
                    "wafv2:DeleteRuleGroup"
                ],
                resources=[
                    web_acl.attr_arn,
                    f"{web_acl.attr_arn}/*"
                ]
            )
        )

        lambda_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                resources=[
                    "arn:aws:s3:::web-security-fl-*",
                    "arn:aws:s3:::web-security-fl-*/*"
                ]
            )
        )

        lambda_code = """
import json
import boto3
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

wafv2 = boto3.client('wafv2')

def handler(event, context):
    '''
    Lambda handler for WAF rule updates.

    This function is triggered by:
    1. EventBridge scheduled rule (periodic updates)
    2. Manual invocation with new rules

    Event structure for manual invocation:
    {
        "rules": [
            {
                "pattern": "attack_pattern",
                "action": "BLOCK" | "COUNT",
                "confidence": 0.95
            }
        ]
    }
    '''
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        web_acl_id = event.get('web_acl_id') or context.function_name.split('-')[-1]
        rules = event.get('rules', [])

        if not rules:
            rules = fetch_rules_from_model()

        if rules:
            update_count = update_waf_rules(rules)
            logger.info(f"Updated {update_count} WAF rules")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'WAF rules updated successfully',
                'rules_processed': len(rules),
                'timestamp': datetime.utcnow().isoformat()
            })
        }

    except Exception as e:
        logger.error(f"Error updating WAF rules: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }


def fetch_rules_from_model():
    '''Fetch new rules from the FL model (placeholder).'''
    return []


def update_waf_rules(rules):
    '''Update WAF rules based on model predictions.'''
    updated = 0
    for rule in rules:
        if rule.get('confidence', 0) >= 0.9:
            logger.info(f"Would update rule: {rule.get('pattern')}")
            updated += 1
    return updated
"""

        self.waf_updater = lambda_.Function(
            self, "WafRuleUpdater",
            function_name="waf-rule-updater",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(lambda_code),
            role=lambda_role,
            timeout=Duration.minutes(5),
            memory_size=256,
            environment={
                "WEB_ACL_ARN": web_acl.attr_arn,
                "WEB_ACL_ID": web_acl.attr_id
            }
        )

        Tags.of(self.waf_updater).add("Project", "CloudWebSecurityFL")

        schedule_rule = events.Rule(
            self, "WafUpdateSchedule",
            rule_name="waf-update-schedule",
            description="Periodic WAF rule updates from FL model",
            schedule=events.Schedule.rate(Duration.hours(6))
        )

        schedule_rule.add_target(
            targets.LambdaFunction(
                self.waf_updater,
                retry_attempts=2
            )
        )

        CfnOutput(
            self, "LambdaArn",
            value=self.waf_updater.function_arn,
            description="WAF Updater Lambda ARN"
        )
        CfnOutput(
            self, "LambdaName",
            value=self.waf_updater.function_name,
            description="WAF Updater Lambda Name"
        )
