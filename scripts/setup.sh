#!/bin/bash
# Setup script for Cloud Web Security with AWS WAF and Federated Learning

set -e

echo "========================================"
echo "Cloud Web Security Setup"
echo "========================================"

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.9"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.9+ required (found $python_version)"
    exit 1
fi
echo "Python version: OK ($python_version)"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Warning: Docker not found. Docker is required for full deployment."
else
    echo "Docker: OK"
fi

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "Warning: AWS CLI not found. Required for AWS deployment."
else
    echo "AWS CLI: OK"
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy

# Create necessary directories
echo "Creating directories..."
mkdir -p data/{sample_traffic,attack_patterns,datasets,models}
mkdir -p data/{org_a,org_b,org_c}
mkdir -p logs

# Generate sample training data
echo "Generating sample training data..."
python scripts/generate_training_data.py --output data/datasets --samples 500
python scripts/generate_training_data.py --org org_a --samples 300
python scripts/generate_training_data.py --org org_b --samples 300
python scripts/generate_training_data.py --org org_c --samples 300

# Create .env file if not exists
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cat > .env << EOF
# Flask Configuration
FLASK_ENV=development
FLASK_APP=web_application.app
SECRET_KEY=dev-secret-key-change-in-production

# AWS Configuration
AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=your-access-key
# AWS_SECRET_ACCESS_KEY=your-secret-key

# Federated Learning
FL_SERVER_HOST=localhost
FL_SERVER_PORT=8080
FL_NUM_ROUNDS=10
FL_MIN_CLIENTS=2

# WAF Configuration
# WAF_WEB_ACL_ID=your-web-acl-id

# Logging
LOG_REQUESTS=true
LOG_DIR=data/sample_traffic
EOF
fi

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate (Linux/Mac)"
echo "                              or: venv\\Scripts\\activate (Windows)"
echo "2. Run web app locally: cd web_application && flask run"
echo "3. Run with Docker: docker-compose up --build"
echo "4. Deploy to AWS: cd infrastructure/cdk && cdk deploy --all"
echo ""
echo "For more information, see README.md"
