"""
Flask Web Application Factory

This module creates and configures the Flask application that will be
protected by AWS WAF. It includes request logging for ML training data.
"""

import os
import logging
from datetime import datetime
from flask import Flask, request, g
from flask_cors import CORS

from .routes import main_bp, api_bp
from .utils import RequestLogger


def create_app(config_name: str = None) -> Flask:
    """
    Application factory for creating Flask app instances.

    Args:
        config_name: Configuration environment (development, production, testing)

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    config_name = config_name or os.environ.get('FLASK_ENV', 'development')

    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
        DEBUG=config_name == 'development',
        TESTING=config_name == 'testing',
        LOG_REQUESTS=os.environ.get('LOG_REQUESTS', 'true').lower() == 'true',
        LOG_DIR=os.environ.get('LOG_DIR', 'data/sample_traffic'),
    )

    CORS(app, origins=['*'] if config_name == 'development' else [])

    logging.basicConfig(
        level=logging.DEBUG if app.config['DEBUG'] else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    app.logger.setLevel(logging.DEBUG if app.config['DEBUG'] else logging.INFO)

    request_logger = RequestLogger(app.config['LOG_DIR'])

    @app.before_request
    def before_request():
        """Log request start time and capture request data."""
        g.start_time = datetime.utcnow()
        g.request_id = request.headers.get('X-Request-ID', str(datetime.utcnow().timestamp()))

    @app.after_request
    def after_request(response):
        """Log request details for ML training data."""
        if app.config['LOG_REQUESTS']:
            duration = (datetime.utcnow() - g.start_time).total_seconds()
            request_logger.log_request(
                request_id=g.request_id,
                method=request.method,
                path=request.path,
                headers=dict(request.headers),
                body=request.get_data(as_text=True)[:1000],
                query_params=dict(request.args),
                source_ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                response_code=response.status_code,
                duration=duration
            )
        return response

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    @app.route('/health')
    def health_check():
        """Health check endpoint for ALB."""
        return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}

    return app
