#!/usr/bin/env python3
"""
Generate Synthetic Training Data

Creates labeled training data for the federated learning model.
Generates both benign and malicious HTTP request patterns.
"""

import json
import random
import os
from datetime import datetime, timedelta
from typing import List, Dict
import argparse
import hashlib


SQL_PATTERNS = [
    "SELECT * FROM users WHERE id=",
    "' OR '1'='1",
    "UNION SELECT",
    "'; DROP TABLE",
    "--",
    "' AND 1=1",
    "ORDER BY 1",
    "EXEC xp_cmdshell",
    "INTO OUTFILE",
    "; INSERT INTO",
]

XSS_PATTERNS = [
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "<iframe>",
    "alert(",
    "document.cookie",
    "<svg onload",
    "eval(",
]

DDOS_CHARACTERISTICS = {
    "high_frequency": True,
    "identical_payloads": True,
    "missing_headers": True,
    "suspicious_ua": ["python-requests", "curl", "wget", "Go-http-client"],
}

BENIGN_PATHS = [
    "/api/users",
    "/api/products",
    "/api/search",
    "/api/login",
    "/api/register",
    "/api/profile",
    "/health",
    "/api/cart",
    "/api/orders",
    "/api/feedback",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0",
]


def generate_benign_request() -> Dict:
    """Generate a benign HTTP request."""
    method = random.choice(["GET", "POST", "GET", "GET"])
    path = random.choice(BENIGN_PATHS)

    body = ""
    if method == "POST":
        if "search" in path:
            body = json.dumps({"query": random.choice(["widget", "product", "item", "tool"])})
        elif "login" in path:
            body = json.dumps({"username": "user123", "password": "pass123"})
        elif "feedback" in path:
            body = json.dumps({"message": "Great service, thanks!"})

    features = {
        "method_encoded": {"GET": 0, "POST": 1}.get(method, 0),
        "path_depth": path.count("/"),
        "path_length": len(path),
        "body_length": len(body),
        "query_length": 0,
        "header_count": random.randint(5, 10),
        "special_chars_body": sum(1 for c in body if c in "';\"<>{}[]|\\"),
        "special_chars_query": 0,
        "sql_keyword_count": 0,
        "xss_keyword_count": 0,
        "has_user_agent": 1,
        "user_agent_length": len(random.choice(USER_AGENTS)),
        "content_type_json": 1 if method == "POST" else 0,
        "has_auth_header": random.choice([0, 1]),
    }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
        "method": method,
        "path": path,
        "source_ip_hash": hashlib.sha256(f"192.168.1.{random.randint(1,254)}".encode()).hexdigest()[:16],
        "response_code": 200,
        "duration_ms": random.uniform(10, 100),
        "features": features,
        "label": "benign"
    }


def generate_sql_injection_request() -> Dict:
    """Generate a SQL injection attack request."""
    method = random.choice(["POST", "GET"])
    path = random.choice(["/api/search", "/api/users", "/api/login"])
    payload = random.choice(SQL_PATTERNS) + str(random.randint(1, 1000))

    body = json.dumps({"query": payload}) if method == "POST" else ""
    query = f"id={payload}" if method == "GET" else ""

    sql_keywords = ["select", "union", "insert", "delete", "drop", "update", "or", "and"]
    sql_count = sum(1 for kw in sql_keywords if kw in payload.lower())

    features = {
        "method_encoded": {"GET": 0, "POST": 1}.get(method, 0),
        "path_depth": path.count("/"),
        "path_length": len(path),
        "body_length": len(body),
        "query_length": len(query),
        "header_count": random.randint(3, 8),
        "special_chars_body": sum(1 for c in body if c in "';\"<>{}[]|\\"),
        "special_chars_query": sum(1 for c in query if c in "';\"<>{}[]|\\"),
        "sql_keyword_count": sql_count,
        "xss_keyword_count": 0,
        "has_user_agent": random.choice([0, 1]),
        "user_agent_length": random.randint(0, 100),
        "content_type_json": 1 if method == "POST" else 0,
        "has_auth_header": 0,
    }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
        "method": method,
        "path": path,
        "source_ip_hash": hashlib.sha256(f"10.0.{random.randint(1,254)}.{random.randint(1,254)}".encode()).hexdigest()[:16],
        "response_code": random.choice([200, 400, 403, 500]),
        "duration_ms": random.uniform(5, 50),
        "features": features,
        "label": "sql_injection"
    }


def generate_xss_request() -> Dict:
    """Generate an XSS attack request."""
    method = "POST"
    path = random.choice(["/api/feedback", "/api/search", "/api/comment"])
    payload = random.choice(XSS_PATTERNS) + f"test{random.randint(1, 100)}"

    body = json.dumps({"message": payload})

    xss_keywords = ["script", "javascript", "onerror", "onload", "onclick", "alert"]
    xss_count = sum(1 for kw in xss_keywords if kw in payload.lower())

    features = {
        "method_encoded": 1,
        "path_depth": path.count("/"),
        "path_length": len(path),
        "body_length": len(body),
        "query_length": 0,
        "header_count": random.randint(4, 8),
        "special_chars_body": sum(1 for c in body if c in "';\"<>{}[]|\\"),
        "special_chars_query": 0,
        "sql_keyword_count": 0,
        "xss_keyword_count": xss_count,
        "has_user_agent": random.choice([0, 1]),
        "user_agent_length": random.randint(0, 80),
        "content_type_json": 1,
        "has_auth_header": 0,
    }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
        "method": method,
        "path": path,
        "source_ip_hash": hashlib.sha256(f"172.16.{random.randint(1,254)}.{random.randint(1,254)}".encode()).hexdigest()[:16],
        "response_code": random.choice([200, 400, 403]),
        "duration_ms": random.uniform(5, 40),
        "features": features,
        "label": "xss"
    }


def generate_ddos_request() -> Dict:
    """Generate a DDoS attack request."""
    method = "GET"
    path = random.choice(["/api/products", "/api/users", "/", "/api/search"])

    features = {
        "method_encoded": 0,
        "path_depth": path.count("/"),
        "path_length": len(path),
        "body_length": 0,
        "query_length": random.randint(0, 50),
        "header_count": random.randint(1, 4),
        "special_chars_body": 0,
        "special_chars_query": random.randint(0, 3),
        "sql_keyword_count": 0,
        "xss_keyword_count": 0,
        "has_user_agent": random.choice([0, 0, 1]),
        "user_agent_length": random.choice([0, 20, 50]),
        "content_type_json": 0,
        "has_auth_header": 0,
    }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
        "method": method,
        "path": path,
        "source_ip_hash": hashlib.sha256(f"10.10.10.{random.randint(1,10)}".encode()).hexdigest()[:16],
        "response_code": random.choice([200, 429, 503]),
        "duration_ms": random.uniform(1, 20),
        "features": features,
        "label": "ddos"
    }


def generate_bot_request() -> Dict:
    """Generate a bot/crawler request."""
    method = "GET"
    path = random.choice(["/robots.txt", "/sitemap.xml", "/.git/config", "/.env", "/admin"])

    features = {
        "method_encoded": 0,
        "path_depth": path.count("/"),
        "path_length": len(path),
        "body_length": 0,
        "query_length": 0,
        "header_count": random.randint(2, 5),
        "special_chars_body": 0,
        "special_chars_query": 0,
        "sql_keyword_count": 0,
        "xss_keyword_count": 0,
        "has_user_agent": 1,
        "user_agent_length": random.randint(10, 30),
        "content_type_json": 0,
        "has_auth_header": 0,
    }

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
        "method": method,
        "path": path,
        "source_ip_hash": hashlib.sha256(f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}".encode()).hexdigest()[:16],
        "response_code": random.choice([200, 404, 403]),
        "duration_ms": random.uniform(5, 30),
        "features": features,
        "label": "bot"
    }


def generate_dataset(
    output_dir: str,
    num_samples: int = 1000,
    distribution: Dict[str, float] = None
) -> None:
    """
    Generate a complete training dataset.

    Args:
        output_dir: Directory to save the dataset
        num_samples: Total number of samples
        distribution: Distribution of attack types
    """
    if distribution is None:
        distribution = {
            "benign": 0.5,
            "sql_injection": 0.15,
            "xss": 0.15,
            "ddos": 0.10,
            "bot": 0.10
        }

    generators = {
        "benign": generate_benign_request,
        "sql_injection": generate_sql_injection_request,
        "xss": generate_xss_request,
        "ddos": generate_ddos_request,
        "bot": generate_bot_request
    }

    os.makedirs(output_dir, exist_ok=True)

    all_samples = []
    for label, ratio in distribution.items():
        count = int(num_samples * ratio)
        generator = generators[label]

        for _ in range(count):
            sample = generator()
            all_samples.append(sample)

    random.shuffle(all_samples)

    date_str = datetime.utcnow().strftime('%Y-%m-%d')
    output_file = os.path.join(output_dir, f"training_data_{date_str}.jsonl")

    with open(output_file, 'w') as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + '\n')

    print(f"Generated {len(all_samples)} samples")
    print(f"Saved to: {output_file}")

    label_counts = {}
    for sample in all_samples:
        label = sample["label"]
        label_counts[label] = label_counts.get(label, 0) + 1

    print("\nDistribution:")
    for label, count in sorted(label_counts.items()):
        print(f"  {label}: {count} ({count/len(all_samples)*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Generate training data for FL model")
    parser.add_argument(
        "--output",
        default="data/datasets",
        help="Output directory"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1000,
        help="Number of samples to generate"
    )
    parser.add_argument(
        "--org",
        help="Organization ID (creates org-specific data)"
    )

    args = parser.parse_args()

    if args.org:
        output_dir = os.path.join("data", args.org)
    else:
        output_dir = args.output

    generate_dataset(output_dir, args.samples)


if __name__ == "__main__":
    main()
