"""
VPC Stack

Creates the Virtual Private Cloud infrastructure with public and
private subnets across multiple availability zones.
"""

from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    CfnOutput,
    Tags
)
from constructs import Construct


class VpcStack(Stack):
    """
    Creates the VPC infrastructure for the web security system.

    Architecture:
    - VPC with CIDR 10.0.0.0/16
    - 2 Availability Zones
    - Public subnets (10.0.1.0/24, 10.0.2.0/24) for ALB
    - Private subnets (10.0.10.0/24, 10.0.11.0/24) for EC2
    - NAT Gateway for private subnet internet access
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = ec2.Vpc(
            self, "WebSecurityVpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                )
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )

        Tags.of(self.vpc).add("Name", "WebSecurityVpc")
        Tags.of(self.vpc).add("Project", "CloudWebSecurityFL")

        self.alb_security_group = ec2.SecurityGroup(
            self, "AlbSecurityGroup",
            vpc=self.vpc,
            description="Security group for Application Load Balancer",
            allow_all_outbound=True
        )
        self.alb_security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
            "Allow HTTP from anywhere"
        )
        self.alb_security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "Allow HTTPS from anywhere"
        )

        self.ec2_security_group = ec2.SecurityGroup(
            self, "Ec2SecurityGroup",
            vpc=self.vpc,
            description="Security group for EC2 instances",
            allow_all_outbound=True
        )
        self.ec2_security_group.add_ingress_rule(
            self.alb_security_group,
            ec2.Port.tcp(5000),
            "Allow traffic from ALB"
        )

        self.fl_security_group = ec2.SecurityGroup(
            self, "FlSecurityGroup",
            vpc=self.vpc,
            description="Security group for Federated Learning components",
            allow_all_outbound=True
        )
        self.fl_security_group.add_ingress_rule(
            self.fl_security_group,
            ec2.Port.tcp(8080),
            "Allow FL traffic within security group"
        )

        CfnOutput(
            self, "VpcId",
            value=self.vpc.vpc_id,
            description="VPC ID"
        )
        CfnOutput(
            self, "PublicSubnets",
            value=",".join([subnet.subnet_id for subnet in self.vpc.public_subnets]),
            description="Public Subnet IDs"
        )
        CfnOutput(
            self, "PrivateSubnets",
            value=",".join([subnet.subnet_id for subnet in self.vpc.private_subnets]),
            description="Private Subnet IDs"
        )
