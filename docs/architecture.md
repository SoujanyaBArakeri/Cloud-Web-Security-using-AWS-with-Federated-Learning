# System Architecture

## Overview

This document describes the architecture of the Cloud Web Security system with AWS WAF and Federated Learning.

## System Components

### 1. Web Application Layer

```
┌─────────────────────────────────────────────────────┐
│                  Web Application                    │
├─────────────────────────────────────────────────────┤
│  Flask Application                                  │
│  ├── Routes (API endpoints)                         │
│  ├── Request Logger (ML data collection)            │
│  ├── Input Validation                               │
│  └── Security Middleware                            │
├─────────────────────────────────────────────────────┤
│  Gunicorn WSGI Server                              │
│  └── Multi-worker process management               │
├─────────────────────────────────────────────────────┤
│  Docker Container                                   │
│  └── Isolated, reproducible environment            │
└─────────────────────────────────────────────────────┘
```

### 2. AWS Infrastructure Layer

```
Internet Traffic
       │
       ▼
┌─────────────────┐
│    AWS WAF      │ ◄── ML-generated rules
│   (WebACL)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      ALB        │  Application Load Balancer
│  (Port 80/443)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   EC2 Fleet     │  Auto Scaling Group
│  (t2.micro)     │  in Private Subnets
└─────────────────┘
```

### 3. Federated Learning Layer

```
┌─────────────────────────────────────────────────────┐
│              Federated Learning System              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │   Org A     │ │   Org B     │ │   Org C     │   │
│  │   Client    │ │   Client    │ │   Client    │   │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘   │
│         │               │               │           │
│         └───────────────┼───────────────┘           │
│                         │                           │
│                         ▼                           │
│               ┌─────────────────┐                   │
│               │  Aggregation    │                   │
│               │  Server         │                   │
│               │  (FedAvg)       │                   │
│               └────────┬────────┘                   │
│                        │                            │
│                        ▼                            │
│               ┌─────────────────┐                   │
│               │  Global Model   │                   │
│               │  Repository     │                   │
│               └─────────────────┘                   │
└─────────────────────────────────────────────────────┘
```

## Data Flow

### Request Processing Flow

```
1. Client Request
       │
       ▼
2. AWS WAF Evaluation
   ├── Managed Rules (SQL, XSS)
   ├── Rate Limiting
   └── ML-Generated Rules
       │
       ▼
3. If Blocked → Return 403
   If Allowed → Continue
       │
       ▼
4. ALB Routes to EC2
       │
       ▼
5. Flask Application
   ├── Request Logging
   ├── Input Validation
   └── Business Logic
       │
       ▼
6. Response to Client
```

### Federated Learning Flow

```
1. FL Server Initializes
   └── Create global model
       │
       ▼
2. Clients Register
   └── Download global model
       │
       ▼
3. Local Training (per client)
   ├── Load local data
   ├── Train for N epochs
   ├── Apply differential privacy
   └── Upload gradients
       │
       ▼
4. Server Aggregation
   ├── Wait for min clients
   ├── Federated averaging
   └── Update global model
       │
       ▼
5. Repeat until converged
       │
       ▼
6. Generate WAF Rules
   └── Deploy to AWS WAF
```

## Security Architecture

### Defense in Depth

```
Layer 1: AWS WAF
├── Managed rule sets
├── Custom ML rules
└── Rate limiting

Layer 2: Network Security
├── VPC isolation
├── Security groups
└── Private subnets

Layer 3: Application Security
├── Input validation
├── Output encoding
└── Authentication

Layer 4: Monitoring
├── CloudWatch metrics
├── WAF logging
└── Request logging
```

### Privacy-Preserving ML

```
┌─────────────────────────────────────────┐
│        Privacy Mechanisms               │
├─────────────────────────────────────────┤
│                                         │
│  1. Data Never Leaves Organization      │
│     └── Only gradients are shared       │
│                                         │
│  2. Differential Privacy                │
│     └── Calibrated noise added          │
│                                         │
│  3. Secure Aggregation                  │
│     └── Cryptographic masking           │
│                                         │
│  4. Gradient Compression                │
│     └── Minimize information leakage    │
│                                         │
└─────────────────────────────────────────┘
```

## Deployment Architecture

### Development Environment

```
docker-compose.yml
├── web_app (Flask)
├── fl_server (Aggregation)
├── fl_client_a/b/c (Organizations)
└── waf_updater (Rule deployment)
```

### Production Environment (AWS)

```
AWS Account
├── VPC (10.0.0.0/16)
│   ├── Public Subnets (ALB)
│   └── Private Subnets (EC2)
├── ALB (internet-facing)
├── WAF WebACL
├── EC2 Auto Scaling Group
├── Lambda (WAF updates)
├── S3 (model artifacts)
└── CloudWatch (monitoring)
```

## Scalability

### Horizontal Scaling

- EC2 Auto Scaling based on CPU utilization
- Multiple FL clients in parallel
- Stateless application design

### Vertical Scaling

- Instance type upgrades
- Enhanced model architectures
- Increased batch sizes

## Monitoring & Observability

```
┌─────────────────────────────────────────┐
│           Monitoring Stack              │
├─────────────────────────────────────────┤
│                                         │
│  CloudWatch Metrics                     │
│  ├── WAF blocked requests               │
│  ├── ALB latency                        │
│  ├── EC2 utilization                    │
│  └── Lambda invocations                 │
│                                         │
│  Application Logs                       │
│  ├── Request logs (ML training data)   │
│  ├── Error logs                         │
│  └── FL training metrics                │
│                                         │
│  Alerts                                 │
│  ├── High block rate                    │
│  ├── Model drift detection              │
│  └── Infrastructure issues              │
│                                         │
└─────────────────────────────────────────┘
```
