"""
Flask Routes

Defines API endpoints for the web application. Includes both legitimate
endpoints and controlled test endpoints for security testing.
"""

from flask import Blueprint, request, jsonify, render_template_string
import html
import re

main_bp = Blueprint('main', __name__)
api_bp = Blueprint('api', __name__)

SAMPLE_DATA = {
    'users': [
        {'id': 1, 'name': 'Alice', 'email': 'alice@example.com'},
        {'id': 2, 'name': 'Bob', 'email': 'bob@example.com'},
        {'id': 3, 'name': 'Charlie', 'email': 'charlie@example.com'},
    ],
    'products': [
        {'id': 1, 'name': 'Widget A', 'price': 29.99},
        {'id': 2, 'name': 'Widget B', 'price': 49.99},
        {'id': 3, 'name': 'Widget C', 'price': 99.99},
    ]
}


@main_bp.route('/')
def index():
    """Home page."""
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloud Web Security Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            h1 { color: #333; }
            .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
            code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>Cloud Web Security with AWS WAF & Federated Learning</h1>
        <p>This is a demo web application protected by AWS WAF with ML-based threat detection.</p>

        <h2>Available Endpoints</h2>
        <div class="endpoint">
            <strong>GET /api/users</strong> - List all users
        </div>
        <div class="endpoint">
            <strong>GET /api/users/&lt;id&gt;</strong> - Get user by ID
        </div>
        <div class="endpoint">
            <strong>GET /api/products</strong> - List all products
        </div>
        <div class="endpoint">
            <strong>POST /api/search</strong> - Search products (JSON body: {"query": "..."})
        </div>
        <div class="endpoint">
            <strong>GET /health</strong> - Health check endpoint
        </div>

        <h2>Security Features</h2>
        <ul>
            <li>AWS WAF protection against SQL injection, XSS, and DDoS</li>
            <li>Federated Learning-based adaptive threat detection</li>
            <li>Request logging for ML model training</li>
            <li>Input validation and sanitization</li>
        </ul>
    </body>
    </html>
    ''')


@api_bp.route('/users', methods=['GET'])
def get_users():
    """Get all users."""
    return jsonify({
        'success': True,
        'data': SAMPLE_DATA['users'],
        'count': len(SAMPLE_DATA['users'])
    })


@api_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id: int):
    """Get user by ID with proper validation."""
    user = next((u for u in SAMPLE_DATA['users'] if u['id'] == user_id), None)
    if user:
        return jsonify({'success': True, 'data': user})
    return jsonify({'success': False, 'error': 'User not found'}), 404


@api_bp.route('/products', methods=['GET'])
def get_products():
    """Get all products."""
    return jsonify({
        'success': True,
        'data': SAMPLE_DATA['products'],
        'count': len(SAMPLE_DATA['products'])
    })


@api_bp.route('/search', methods=['POST'])
def search_products():
    """
    Search products with input validation.
    Demonstrates proper handling to prevent SQL injection.
    """
    data = request.get_json()
    if not data or 'query' not in data:
        return jsonify({'success': False, 'error': 'Query parameter required'}), 400

    query = data['query']

    if not isinstance(query, str) or len(query) > 100:
        return jsonify({'success': False, 'error': 'Invalid query'}), 400

    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
        r"(--|;|'|\"|\\)",
        r"(\bOR\b.*=.*)",
        r"(\bAND\b.*=.*)",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return jsonify({
                'success': False,
                'error': 'Invalid characters in query',
                'blocked': True,
                'reason': 'potential_sql_injection'
            }), 400

    sanitized_query = html.escape(query.lower().strip())

    results = [
        p for p in SAMPLE_DATA['products']
        if sanitized_query in p['name'].lower()
    ]

    return jsonify({
        'success': True,
        'query': sanitized_query,
        'data': results,
        'count': len(results)
    })


@api_bp.route('/feedback', methods=['POST'])
def submit_feedback():
    """
    Submit feedback with XSS protection.
    Demonstrates proper output encoding.
    """
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'success': False, 'error': 'Message required'}), 400

    message = data['message']

    if not isinstance(message, str) or len(message) > 1000:
        return jsonify({'success': False, 'error': 'Invalid message'}), 400

    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
    ]
    for pattern in xss_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return jsonify({
                'success': False,
                'error': 'Invalid content detected',
                'blocked': True,
                'reason': 'potential_xss'
            }), 400

    safe_message = html.escape(message)

    return jsonify({
        'success': True,
        'message': 'Feedback received',
        'sanitized_content': safe_message
    })


@api_bp.route('/login', methods=['POST'])
def login():
    """
    Login endpoint with rate limiting awareness.
    In production, this would be protected by WAF rate limiting.
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Credentials required'}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'}), 400

    if username == 'admin' and password == 'demo123':
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': 'demo-jwt-token-would-go-here'
        })

    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get application statistics."""
    return jsonify({
        'success': True,
        'data': {
            'total_users': len(SAMPLE_DATA['users']),
            'total_products': len(SAMPLE_DATA['products']),
            'waf_enabled': True,
            'fl_model_version': '1.0.0'
        }
    })
