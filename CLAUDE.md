# Cloud Web Security with AWS WAF and Federated Learning

## Project Overview
A secure cloud-based web security system using Amazon Web Services AWS WAF integrated with Federated Learning. Organizations collaboratively detect cyber threats by sharing only model updates instead of sensitive traffic data.

## Architecture
- **Infrastructure**: AWS CDK (Python) for IaC
- **Web Framework**: Flask
- **ML Framework**: PyTorch for Federated Learning
- **Container Orchestration**: Docker Compose
- **Cloud Services**: AWS EC2, ALB, WAF, Lambda, S3, CloudWatch

## Directory Structure
- `infrastructure/cdk/` - AWS CDK stacks for cloud resources
- `federated_learning/` - FL server, client, models, and security modules
- `web_application/` - Flask web application (protected by WAF)
- `waf_integration/` - WAF rule generation and updates
- `monitoring/` - CloudWatch dashboards and alerting
- `scripts/` - Deployment and simulation scripts
- `tests/` - Unit, integration, and security tests

## Development Commands
```bash
# Install dependencies
pip install -r requirements.txt

# Run web application locally
cd web_application && flask run

# Run with Docker
docker-compose up --build

# Run federated learning simulation
python -m federated_learning.server.aggregation_server

# Deploy infrastructure
cd infrastructure/cdk && cdk deploy --all

# Run tests
pytest tests/

# Simulate attacks (for testing)
python scripts/simulate_attacks.py
```

## Key Files
- `federated_learning/models/threat_detection_model.py` - Neural network for threat classification
- `federated_learning/server/aggregation_server.py` - Federated averaging implementation
- `waf_integration/rule_generator.py` - Converts ML predictions to WAF rules
- `infrastructure/cdk/stacks/waf_stack.py` - AWS WAF configuration

## Environment Variables
- `AWS_REGION` - AWS region (default: us-east-1)
- `AWS_ACCESS_KEY_ID` - AWS credentials
- `AWS_SECRET_ACCESS_KEY` - AWS credentials
- `FLASK_ENV` - development/production
- `FL_SERVER_HOST` - Federated learning server address
- `WAF_WEB_ACL_ID` - AWS WAF WebACL ID

## Testing
- Unit tests in `tests/unit/`
- Integration tests in `tests/integration/`
- Security tests in `tests/security/`
- Attack simulation via `scripts/simulate_attacks.py`
