"""
ALB Stack

Creates the Application Load Balancer to distribute traffic
to EC2 instances and integrate with AWS WAF.
"""

from aws_cdk import (
    Stack,
    Duration,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_autoscaling as autoscaling,
    CfnOutput,
    Tags
)
from constructs import Construct


class AlbStack(Stack):
    """
    Creates Application Load Balancer infrastructure.

    Features:
    - Internet-facing ALB in public subnets
    - HTTP listener (port 80)
    - Health checks for target group
    - Integration point for AWS WAF
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.Vpc,
        security_group: ec2.SecurityGroup,
        asg: autoscaling.AutoScalingGroup,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.alb = elbv2.ApplicationLoadBalancer(
            self, "WebSecurityAlb",
            vpc=vpc,
            internet_facing=True,
            security_group=security_group,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC
            ),
            load_balancer_name="web-security-alb"
        )

        Tags.of(self.alb).add("Name", "WebSecurityALB")
        Tags.of(self.alb).add("Project", "CloudWebSecurityFL")

        self.target_group = elbv2.ApplicationTargetGroup(
            self, "WebAppTargetGroup",
            vpc=vpc,
            port=5000,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.INSTANCE,
            health_check=elbv2.HealthCheck(
                path="/health",
                port="5000",
                protocol=elbv2.Protocol.HTTP,
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
                timeout=Duration.seconds(5),
                interval=Duration.seconds(30)
            ),
            deregistration_delay=Duration.seconds(30)
        )

        asg.attach_to_application_target_group(self.target_group)

        self.listener = self.alb.add_listener(
            "HttpListener",
            port=80,
            protocol=elbv2.ApplicationProtocol.HTTP,
            default_target_groups=[self.target_group]
        )

        CfnOutput(
            self, "AlbArn",
            value=self.alb.load_balancer_arn,
            description="ALB ARN (needed for WAF association)"
        )
        CfnOutput(
            self, "AlbDnsName",
            value=self.alb.load_balancer_dns_name,
            description="ALB DNS Name"
        )
        CfnOutput(
            self, "AlbUrl",
            value=f"http://{self.alb.load_balancer_dns_name}",
            description="Application URL"
        )
