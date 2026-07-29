"""
Utility functions for the web application.

Includes request logging for generating ML training data.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
import hashlib


class RequestLogger:
    """
    Logs HTTP requests in a format suitable for ML model training.

    Each request is logged with features that can be used to train
    the federated learning threat detection model.
    """

    def __init__(self, log_dir: str):
        """
        Initialize the request logger.

        Args:
            log_dir: Directory to store log files
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

    def _get_log_file(self) -> str:
        """Get the log file path for today."""
        date_str = datetime.utcnow().strftime('%Y-%m-%d')
        return os.path.join(self.log_dir, f'requests_{date_str}.jsonl')

    def _extract_features(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: str,
        query_params: Dict[str, str],
        user_agent: str
    ) -> Dict[str, Any]:
        """
        Extract features from a request for ML training.

        These features are used by the threat detection model to classify
        requests as benign or malicious.
        """
        body_length = len(body) if body else 0
        query_length = sum(len(k) + len(v) for k, v in query_params.items())

        special_chars_body = sum(1 for c in body if c in "';\"<>{}[]|\\") if body else 0
        special_chars_query = sum(
            1 for c in str(query_params) if c in "';\"<>{}[]|\\"
        )

        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'or', 'and']
        xss_keywords = ['script', 'javascript', 'onerror', 'onload', 'onclick', 'alert']

        body_lower = body.lower() if body else ''
        sql_keyword_count = sum(1 for kw in sql_keywords if kw in body_lower)
        xss_keyword_count = sum(1 for kw in xss_keywords if kw in body_lower)

        return {
            'method_encoded': {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3}.get(method, 4),
            'path_depth': path.count('/'),
            'path_length': len(path),
            'body_length': body_length,
            'query_length': query_length,
            'header_count': len(headers),
            'special_chars_body': special_chars_body,
            'special_chars_query': special_chars_query,
            'sql_keyword_count': sql_keyword_count,
            'xss_keyword_count': xss_keyword_count,
            'has_user_agent': 1 if user_agent else 0,
            'user_agent_length': len(user_agent) if user_agent else 0,
            'content_type_json': 1 if 'application/json' in headers.get('Content-Type', '') else 0,
            'has_auth_header': 1 if 'Authorization' in headers else 0,
        }

    def log_request(
        self,
        request_id: str,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: str,
        query_params: Dict[str, str],
        source_ip: str,
        user_agent: str,
        response_code: int,
        duration: float,
        label: Optional[str] = None
    ) -> None:
        """
        Log a request with extracted features.

        Args:
            request_id: Unique request identifier
            method: HTTP method
            path: Request path
            headers: Request headers
            body: Request body (truncated)
            query_params: Query parameters
            source_ip: Client IP address
            user_agent: User agent string
            response_code: HTTP response code
            duration: Request duration in seconds
            label: Optional label for supervised learning (benign, sql_injection, xss, etc.)
        """
        ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()[:16]

        features = self._extract_features(
            method, path, headers, body, query_params, user_agent
        )

        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': request_id,
            'method': method,
            'path': path,
            'source_ip_hash': ip_hash,
            'response_code': response_code,
            'duration_ms': round(duration * 1000, 2),
            'features': features,
            'label': label,
        }

        log_file = self._get_log_file()
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')


def is_safe_path(path: str) -> bool:
    """Check if a path is safe (no directory traversal)."""
    normalized = os.path.normpath(path)
    return not normalized.startswith('..') and not normalized.startswith('/')


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize user input by removing potentially dangerous characters.

    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized text
    """
    import html
    if not isinstance(text, str):
        return ''
    text = text[:max_length]
    text = html.escape(text)
    return text
