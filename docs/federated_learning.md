# Federated Learning Documentation

## Overview

This document explains the Federated Learning (FL) implementation for privacy-preserving collaborative threat detection.

## What is Federated Learning?

Federated Learning is a machine learning approach where:

1. **Data stays local**: Each organization keeps its data on-premises
2. **Model travels**: Only model updates (gradients) are shared
3. **Privacy preserved**: No raw data is exposed to other parties
4. **Collaborative learning**: All participants benefit from collective intelligence

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    FL System Architecture                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  Aggregation    │    │  Global Model   │                │
│  │  Server         │◄──►│  Repository     │                │
│  └────────┬────────┘    └─────────────────┘                │
│           │                                                 │
│           │ HTTP API                                        │
│           │                                                 │
│  ┌────────┼────────────────────────────────┐               │
│  │        │                                │               │
│  ▼        ▼                        ▼       │               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │  Client A  │  │  Client B  │  │  Client C  │            │
│  │            │  │            │  │            │            │
│  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │            │
│  │ │ Local  │ │  │ │ Local  │ │  │ │ Local  │ │            │
│  │ │ Model  │ │  │ │ Model  │ │  │ │ Model  │ │            │
│  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │            │
│  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │            │
│  │ │ Local  │ │  │ │ Local  │ │  │ │ Local  │ │            │
│  │ │ Data   │ │  │ │ Data   │ │  │ │ Data   │ │            │
│  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Training Process

### Federated Averaging (FedAvg)

The core algorithm used is Federated Averaging:

```
Algorithm: FedAvg
─────────────────────────────────────────────────
1. Server initializes global model W₀

2. For each round t = 1, 2, ..., T:
   
   a. Server sends Wₜ to selected clients
   
   b. Each client k:
      - Downloads Wₜ
      - Trains on local data for E epochs
      - Computes update: ΔWₖ = Wₜ₊₁,ₖ - Wₜ
      - Applies privacy mechanisms
      - Uploads ΔWₖ to server
   
   c. Server aggregates:
      Wₜ₊₁ = Wₜ + Σₖ (nₖ/n) × ΔWₖ
      
      where nₖ = samples at client k
            n  = total samples

3. Return final model Wₜ
```

### Training Round Lifecycle

```
┌──────────────────────────────────────────────────────┐
│                   Training Round                     │
├──────────────────────────────────────────────────────┤
│                                                      │
│  1. Model Distribution                               │
│     Server → Clients                                 │
│     ├── Send global model weights                    │
│     └── Include round number, version               │
│                                                      │
│  2. Local Training (Parallel)                        │
│     Each Client:                                     │
│     ├── Load local dataset                           │
│     ├── Train for E epochs                           │
│     ├── Compute gradients                            │
│     └── Apply differential privacy                   │
│                                                      │
│  3. Update Collection                                │
│     Clients → Server                                 │
│     ├── Upload encrypted gradients                   │
│     ├── Include sample count                         │
│     └── Include training metrics                     │
│                                                      │
│  4. Aggregation                                      │
│     Server:                                          │
│     ├── Wait for min_clients                         │
│     ├── Compute weighted average                     │
│     └── Update global model                          │
│                                                      │
│  5. Checkpoint                                       │
│     ├── Save model to disk                           │
│     └── Log round metrics                            │
│                                                      │
└──────────────────────────────────────────────────────┘
```

## Threat Detection Model

### Architecture

```python
ThreatDetectionModel:
    Input Layer (14 features)
         │
         ▼
    Linear(14, 64) + BatchNorm + ReLU + Dropout
         │
         ▼
    Linear(64, 128) + BatchNorm + ReLU + Dropout
         │
         ▼
    Linear(128, 64) + BatchNorm + ReLU + Dropout
         │
         ▼
    Linear(64, 32) + BatchNorm + ReLU + Dropout
         │
         ▼
    Output Layer: Linear(32, 5)
         │
         ▼
    Softmax → [benign, sql_injection, xss, ddos, bot]
```

### Input Features

| Feature | Description |
|---------|-------------|
| method_encoded | HTTP method (0=GET, 1=POST, etc.) |
| path_depth | Number of path segments |
| path_length | Length of URL path |
| body_length | Request body size |
| query_length | Query string length |
| header_count | Number of headers |
| special_chars_body | Special characters in body |
| special_chars_query | Special characters in query |
| sql_keyword_count | SQL keywords detected |
| xss_keyword_count | XSS keywords detected |
| has_user_agent | User-Agent header present |
| user_agent_length | User-Agent string length |
| content_type_json | Content-Type is JSON |
| has_auth_header | Authorization header present |

## Privacy Mechanisms

### 1. Differential Privacy

```
┌─────────────────────────────────────────────────────┐
│             Differential Privacy                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Step 1: Gradient Clipping                          │
│  ─────────────────────────                          │
│  Bound sensitivity by clipping gradient norm:       │
│  g' = g × min(1, C/||g||)                          │
│                                                     │
│  Step 2: Noise Addition                             │
│  ─────────────────────────                          │
│  Add calibrated Gaussian noise:                     │
│  g'' = g' + N(0, σ²C²/n)                           │
│                                                     │
│  where:                                             │
│  - C = max gradient norm                            │
│  - σ = noise multiplier                             │
│  - n = number of samples                            │
│                                                     │
│  Privacy Guarantee: (ε, δ)-differential privacy     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### 2. Secure Aggregation

```
┌─────────────────────────────────────────────────────┐
│             Secure Aggregation                      │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Goal: Server learns only the SUM of updates,       │
│        not individual contributions                 │
│                                                     │
│  Method: Pairwise Masking                           │
│  ─────────────────────────                          │
│                                                     │
│  1. Each pair (i,j) agrees on random mask Mᵢⱼ       │
│                                                     │
│  2. Client i adds: +Mᵢⱼ for all j > i              │
│                    -Mᵢⱼ for all j < i              │
│                                                     │
│  3. When summed: masks cancel out!                  │
│     Σᵢ masked_updateᵢ = Σᵢ updateᵢ                 │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## API Reference

### Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Server health check |
| `/register` | POST | Register a new client |
| `/model` | GET | Download current global model |
| `/update` | POST | Upload model update |
| `/status` | GET | Get training status |
| `/start` | POST | Start training |
| `/stop` | POST | Stop training |
| `/metrics` | GET | Get training metrics |

### Client Operations

```python
# Initialize client
trainer = LocalTrainer(
    org_id="org_a",
    server_host="localhost",
    server_port=8080,
    data_path="data/org_a",
    local_epochs=5
)

# Register with server
trainer.register()

# Participate in one round
trainer.participate_round()

# Run continuous training
trainer.run(num_rounds=10)
```

## Configuration

### Server Configuration

```python
AggregationServer(
    num_rounds=10,          # Total training rounds
    min_clients=2,          # Minimum clients per round
    model_save_path="models"  # Model checkpoint directory
)
```

### Client Configuration

```python
LocalTrainer(
    org_id="org_a",         # Organization identifier
    server_host="fl_server", # Server hostname
    server_port=8080,        # Server port
    data_path="data/org_a",  # Local data directory
    local_epochs=5,          # Epochs per round
    learning_rate=0.001,     # Learning rate
    batch_size=32            # Batch size
)
```

### Privacy Configuration

```python
DifferentialPrivacy(
    epsilon=1.0,            # Privacy budget
    delta=1e-5,             # Privacy parameter
    max_grad_norm=1.0       # Gradient clipping bound
)
```

## Metrics and Monitoring

### Training Metrics

- **Loss**: Cross-entropy loss per round
- **Accuracy**: Validation accuracy per round
- **Participation**: Number of clients per round
- **Convergence**: Model weight changes over time

### Privacy Metrics

- **Privacy Budget**: Cumulative epsilon spent
- **Gradient Norm**: Pre/post clipping statistics
- **Noise Level**: Actual noise added

## Best Practices

1. **Data Quality**: Ensure balanced class distribution locally
2. **Hyperparameters**: Start with conservative learning rates
3. **Privacy Budget**: Monitor cumulative privacy loss
4. **Synchronization**: Handle client dropouts gracefully
5. **Model Versioning**: Track model versions carefully

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Model divergence | Reduce learning rate, increase min_clients |
| Slow convergence | Increase local epochs, check data quality |
| Privacy budget exceeded | Reduce rounds or increase epsilon |
| Client timeout | Increase server timeout, check network |
