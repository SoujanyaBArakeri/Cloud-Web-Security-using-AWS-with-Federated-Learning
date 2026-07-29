#!/usr/bin/env python3
"""
AWS CDK Application Entry Point

Deploys the complete infrastructure for Cloud Web Security
with AWS WAF and Federated Learning.
"""

import aws_cdk as cdk
from stacks.vpc_stack import VpcStack
from stacks.ec2_stack import Ec2Stack
from stacks.alb_stack import AlbStack
from stacks.waf_stack import WafStack
from stacks.lambda_stack import LambdaStack


def main():
    """Create and deploy all CDK stacks."""
    app = cdk.App()

    env = cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region") or "us-east-1"
    )

    vpc_stack = VpcStack(
        app, "WebSecurityVpcStack",
        env=env,
        description="VPC infrastructure for Cloud Web Security"
    )

    ec2_stack = Ec2Stack(
        app, "WebSecurityEc2Stack",
        vpc=vpc_stack.vpc,
        security_group=vpc_stack.ec2_security_group,
        env=env,
        description="EC2 Auto Scaling for web application"
    )
    ec2_stack.add_dependency(vpc_stack)

    alb_stack = AlbStack(
        app, "WebSecurityAlbStack",
        vpc=vpc_stack.vpc,
        security_group=vpc_stack.alb_security_group,
        asg=ec2_stack.asg,
        env=env,
        description="Application Load Balancer"
    )
    alb_stack.add_dependency(ec2_stack)

    waf_stack = WafStack(
        app, "WebSecurityWafStack",
        alb=alb_stack.alb,
        env=env,
        description="AWS WAF WebACL for threat protection"
    )
    waf_stack.add_dependency(alb_stack)

    lambda_stack = LambdaStack(
        app, "WebSecurityLambdaStack",
        web_acl=waf_stack.web_acl,
        env=env,
        description="Lambda for WAF rule updates from FL model"
    )
    lambda_stack.add_dependency(waf_stack)

    cdk.Tags.of(app).add("Project", "CloudWebSecurityFL")
    cdk.Tags.of(app).add("Environment", "Development")

    app.synth()


if __name__ == "__main__":
    main()
