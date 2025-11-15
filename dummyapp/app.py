#!/usr/bin/env python3
"""
Dummy Python application for SBOM generation testing.
"""

from flask import Flask, jsonify
import requests
import yaml

app = Flask(__name__)

@app.route("/")
def hello():
    return jsonify({
        "message": "Hello from Sharing SBOM System",
        "version": "1.0.0",
        "status": "running"
    })

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

