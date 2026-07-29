"""
EC2 Stack

Creates EC2 instances with Auto Scaling for the web application.
Uses t2.micro instances for AWS Free Tier eligibility.
"""

from aws_cdk import (
    Stack,
    Duration,
    aws_ec2 as ec2,
    aws_autoscaling as autoscaling,
    aws_iam as iam,
    CfnOutput,
    Tags
)
from constructs import Construct


class Ec2Stack(Stack):
    """
    Creates EC2 Auto Scaling Group for the web application.

    Features:
    - t2.micro instances (Free Tier eligible)
    - Auto Scaling from 1-3 instances
    - IAM role with necessary permissions
    - User data script for application setup
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        vpc: ec2.Vpc,
        security_group: ec2.SecurityGroup,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        role = iam.Role(
            self, "Ec2Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            description="Role for web application EC2 instances"
        )

        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
        )
        role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy")
        )

        role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                resources=["arn:aws:s3:::web-security-fl-*"]
            )
        )

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "#!/bin/bash",
            "set -e",

            "yum update -y",
            "yum install -y python3 python3-pip docker git",

            "systemctl start docker",
            "systemctl enable docker",
            "usermod -a -G docker ec2-user",

            "pip3 install flask gunicorn boto3",

            "mkdir -p /app",
            "cd /app",

            "cat > /app/health_check.py << 'EOF'",
            "from flask import Flask, jsonify",
            "app = Flask(__name__)",
            "@app.route('/health')",
            "def health():",
            "    return jsonify({'status': 'healthy'})",
            "if __name__ == '__main__':",
            "    app.run(host='0.0.0.0', port=5000)",
            "EOF",

            "python3 /app/health_check.py &",

            "echo 'EC2 setup complete'"
        )

        ami = ec2.MachineImage.latest_amazon_linux2()

        self.asg = autoscaling.AutoScalingGroup(
            self, "WebAppAsg",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T2,
                ec2.InstanceSize.MICRO
            ),
            machine_image=ami,
            security_group=security_group,
            role=role,
            user_data=user_data,
            min_capacity=1,
            max_capacity=3,
            desired_capacity=1,
            health_check=autoscaling.HealthCheck.ec2(
                grace=Duration.minutes(5)
            ),
            update_policy=autoscaling.UpdatePolicy.rolling_update(
                max_batch_size=1,
                min_instances_in_service=1,
                pause_time=Duration.minutes(5)
            )
        )

        self.asg.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=70,
            cooldown=Duration.minutes(5)
        )

        Tags.of(self.asg).add("Name", "WebSecurityApp")
        Tags.of(self.asg).add("Project", "CloudWebSecurityFL")

        CfnOutput(
            self, "AsgName",
            value=self.asg.auto_scaling_group_name,
            description="Auto Scaling Group Name"
        )
