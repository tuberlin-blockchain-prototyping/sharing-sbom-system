#!/usr/bin/env python3
import os
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask, jsonify
from config import Config
from models import db
from routes import bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
    
    app.register_blueprint(bp, url_prefix="")
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found"}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500
    
    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
