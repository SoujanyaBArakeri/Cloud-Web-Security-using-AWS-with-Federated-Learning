#!/usr/bin/env python3
"""Run the Flask web application."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web_application'))

from app import create_app

if __name__ == '__main__':
    app = create_app()
    print("\n" + "="*60)
    print("Cloud Web Security Application")
    print("="*60)
    print(f"Running at: http://localhost:5000")
    print(f"Health check: http://localhost:5000/health")
    print(f"API docs: http://localhost:5000/")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
