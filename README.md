
# Cloud Web Security with AWS WAF and Federated Learning

A secure cloud-based web security system using Amazon Web Services AWS WAF integrated with Federated Learning. Organizations collaboratively detect cyber threats by sharing only model updates instead of sensitive traffic data.

## Problem Statement

Developing a secure cloud-based web security system using Amazon Web Services AWS WAF integrated with Federated Learning, where organizations collaboratively detect cyber threats by sharing only model updates instead of sensitive traffic data.

## Objectives

1. **Secure Cloud Infrastructure**: Deploy scalable web application using AWS EC2, Application Load Balancer, and AWS WAF
2. **Privacy-Preserving ML**: Implement Federated Learning for collaborative threat detection without sharing raw traffic data
3. **Decentralized Training**: Enable ML model training across multiple organizations
4. **Adaptive Security**: Real-time WAF rule updates based on federated learning insights
5. **Comprehensive Protection**: Guard against SQL injection, XSS, DDoS, and bot attacks

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FEDERATED LEARNING LAYER                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Org A      │  │   Org B      │  │   Org C      │          │
│  │ Local Model  │  │ Local Model  │  │ Local Model  │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         └────────────┬────┴────┬────────────┘                   │
│              ┌───────▼─────────▼───────┐                        │
│              │  Aggregation Server     │                        │
│              │  (Federated Averaging)  │                        │
│              └───────────┬─────────────┘                        │
│                          ▼                                      │
│              ┌───────────────────────┐                          │
│              │   WAF Rule Generator  │                          │
│              └───────────┬───────────┘                          │
└──────────────────────────┼──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AWS CLOUD LAYER                            │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │  AWS WAF    │◄──│  Lambda     │◄──│  Rule Updates       │   │
│  └──────┬──────┘   └─────────────┘   └─────────────────────┘   │
│         ▼                                                       │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │     ALB     │──►│    EC2      │──►│      Database       │   │
│  └─────────────┘   └─────────────┘   └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
cloud-web-security-fl/
├── infrastructure/cdk/        # AWS CDK infrastructure
│   ├── stacks/
│   │   ├── vpc_stack.py       # VPC, subnets, security groups
│   │   ├── ec2_stack.py       # EC2 Auto Scaling
│   │   ├── alb_stack.py       # Application Load Balancer
│   │   ├── waf_stack.py       # AWS WAF WebACL
│   │   └── lambda_stack.py    # WAF update Lambda
│   └── app.py                 # CDK app entry point
│
├── federated_learning/        # Federated Learning implementation
│   ├── models/                # ML model definitions
│   │   ├── threat_detection_model.py
│   │   └── base_model.py
│   ├── server/                # FL aggregation server
│   │   ├── aggregation_server.py
│   │   └── federated_averaging.py
│   ├── client/                # FL client for organizations
│   │   ├── local_trainer.py
│   │   └── data_preprocessor.py
│   └── security/              # Privacy mechanisms
│       ├── differential_privacy.py
│       └── secure_aggregation.py
│
├── web_application/           # Flask web application
│   └── app/
│       ├── __init__.py
│       ├── routes.py
│       └── utils.py
│
├── waf_integration/           # WAF rule management
│   ├── rule_generator.py
│   ├── waf_updater.py
│   └── rule_templates/
│
├── scripts/                   # Utility scripts
│   ├── setup.sh
│   ├── simulate_attacks.py
│   └── generate_training_data.py
│
├── docker-compose.yml         # Multi-container orchestration
└── requirements.txt           # Python dependencies
```

## Quick Start

### Prerequisites

- Python 3.9+
- Docker & Docker Compose
- AWS CLI (for cloud deployment)
- AWS CDK (for infrastructure deployment)

### Local Development

1. **Clone and setup:**
```bash
cd "Cloud web security using  AWS Waf with Federative Learning"
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Generate training data:**
```bash
python scripts/generate_training_data.py --samples 1000
```

3. **Run with Docker Compose:**
```bash
docker-compose up --build
```

4. **Access the application:**
- Web App: http://localhost:5000
- FL Server: http://localhost:8080

### Test the Security

```bash
# Run attack simulation
python scripts/simulate_attacks.py --url http://localhost:5000 --attack all
```

## AWS Deployment

### Prerequisites

```bash
# Install AWS CDK
npm install -g aws-cdk

# Configure AWS credentials
aws configure
```

### Deploy Infrastructure

```bash
cd infrastructure/cdk
pip install -r requirements.txt

# Preview changes
cdk synth
cdk diff

# Deploy all stacks
cdk deploy --all
```

## Key Features

### Federated Learning

- **Privacy-Preserving**: Organizations share only model gradients, not raw data
- **Differential Privacy**: Calibrated noise added to gradients
- **Secure Aggregation**: Cryptographic protocols protect individual updates
- **Federated Averaging**: Weighted aggregation of model updates

### ML-Based Threat Detection

- **Neural Network Classifier**: Detects SQL injection, XSS, DDoS, bot attacks
- **Feature Engineering**: 14 features extracted from HTTP requests
- **Real-time Inference**: Sub-millisecond prediction latency
- **Continuous Learning**: Model improves with each FL round

### AWS WAF Integration

- **Managed Rules**: AWS-managed rule sets for common threats
- **Custom Rules**: ML-generated rules from FL model
- **Rate Limiting**: DDoS protection with configurable thresholds
- **Automatic Updates**: Lambda-based rule deployment

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/health` | GET | Health check |
| `/api/users` | GET | List users |
| `/api/products` | GET | List products |
| `/api/search` | POST | Search products |
| `/api/feedback` | POST | Submit feedback |
| `/api/login` | POST | User login |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Flask environment | development |
| `AWS_REGION` | AWS region | us-east-1 |
| `FL_SERVER_HOST` | FL server hostname | localhost |
| `FL_SERVER_PORT` | FL server port | 8080 |
| `FL_NUM_ROUNDS` | Number of FL rounds | 10 |
| `FL_MIN_CLIENTS` | Minimum clients per round | 2 |

## Security Considerations

- **Input Validation**: All user inputs are validated and sanitized
- **XSS Protection**: HTML encoding on all outputs
- **SQL Injection Prevention**: Parameterized queries (demo uses in-memory data)
- **Rate Limiting**: Protection against DDoS attacks
- **Privacy**: No raw data leaves organization boundaries

## AWS Cost Estimation (Free Tier)

| Service | Usage | Cost |
|---------|-------|------|
| EC2 (t2.micro) | 750 hours/month | Free |
| ALB | 750 hours/month | Free* |
| WAF | WebACL + rules | ~$5-10/month |
| Lambda | 1M requests | Free |
| S3 | 5GB storage | Free |

*ALB data processing charges may apply

## Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run all tests with coverage
pytest --cov=. tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is for educational purposes.

## References

- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/)
- [Federated Learning Paper](https://arxiv.org/abs/1602.05629)
- [Differential Privacy](https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf)
