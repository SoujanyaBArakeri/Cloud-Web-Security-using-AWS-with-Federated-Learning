"""
AWS WAF Stack

Creates AWS WAF WebACL with managed rules for protection against
common web attacks like SQL injection, XSS, and known bad inputs.
"""

from aws_cdk import (
    Stack,
    aws_wafv2 as wafv2,
    aws_elasticloadbalancingv2 as elbv2,
    CfnOutput,
    Tags
)
from constructs import Construct


class WafStack(Stack):
    """
    Creates AWS WAF WebACL for web application protection.

    Rules included:
    1. AWS Managed Rules - Common Rule Set (SQL injection, XSS)
    2. AWS Managed Rules - Known Bad Inputs
    3. AWS Managed Rules - SQL Injection
    4. Rate limiting rule (DDoS protection)
    5. Custom rules placeholder for ML-generated rules
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        alb: elbv2.ApplicationLoadBalancer,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.web_acl = wafv2.CfnWebACL(
            self, "WebSecurityAcl",
            name="web-security-acl",
            description="WAF ACL for Cloud Web Security with Federated Learning",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(
                allow=wafv2.CfnWebACL.AllowActionProperty()
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="WebSecurityAclMetrics",
                sampled_requests_enabled=True
            ),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesCommonRuleSet",
                    priority=1,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        none={}
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="CommonRuleSetMetrics",
                        sampled_requests_enabled=True
                    )
                ),

                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesSQLiRuleSet",
                    priority=2,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        none={}
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesSQLiRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="SQLiRuleSetMetrics",
                        sampled_requests_enabled=True
                    )
                ),

                wafv2.CfnWebACL.RuleProperty(
                    name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
                    priority=3,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        none={}
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="KnownBadInputsMetrics",
                        sampled_requests_enabled=True
                    )
                ),

                wafv2.CfnWebACL.RuleProperty(
                    name="RateLimitRule",
                    priority=4,
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        block=wafv2.CfnWebACL.BlockActionProperty()
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            limit=2000,
                            aggregate_key_type="IP"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="RateLimitMetrics",
                        sampled_requests_enabled=True
                    )
                ),

                wafv2.CfnWebACL.RuleProperty(
                    name="FederatedLearningCustomRules",
                    priority=10,
                    action=wafv2.CfnWebACL.RuleActionProperty(
                        count=wafv2.CfnWebACL.CountActionProperty()
                    ),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        byte_match_statement=wafv2.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=wafv2.CfnWebACL.FieldToMatchProperty(
                                uri_path={}
                            ),
                            positional_constraint="CONTAINS",
                            search_string="FL_PLACEHOLDER",
                            text_transformations=[
                                wafv2.CfnWebACL.TextTransformationProperty(
                                    priority=0,
                                    type="LOWERCASE"
                                )
                            ]
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="FLCustomRuleMetrics",
                        sampled_requests_enabled=True
                    )
                )
            ]
        )

        Tags.of(self.web_acl).add("Project", "CloudWebSecurityFL")

        self.waf_association = wafv2.CfnWebACLAssociation(
            self, "WafAlbAssociation",
            resource_arn=alb.load_balancer_arn,
            web_acl_arn=self.web_acl.attr_arn
        )

        CfnOutput(
            self, "WebAclArn",
            value=self.web_acl.attr_arn,
            description="WAF WebACL ARN"
        )
        CfnOutput(
            self, "WebAclId",
            value=self.web_acl.attr_id,
            description="WAF WebACL ID"
        )
