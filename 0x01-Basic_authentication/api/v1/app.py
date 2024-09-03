#!/usr/bin/env python3
"""
Route module for the API
"""
import os
from os import getenv

from flask import Flask, abort, jsonify, request
from flask_cors import CORS, cross_origin

from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.views import app_views

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

if getenv("AUTH_TYPE") == "auth":
    auth = Auth()
if getenv("AUTH_TYPE") == "basic_auth":
    auth = BasicAuth()


@app.before_request
def filtering_request():
    """
    Filter the incoming request based on authentication and authorization.

    Returns:
        None: If the authentication is not required for the requested path.
        None: If the authentication is required but not provided.
        None: If the authentication is provided but the user is not authorized.
    """

    if auth is None:
        return

    paths = ["/api/v1/status/", "/api/v1/unauthorized/", "/api/v1/forbidden/"]

    if not auth.require_auth(request.path, paths):
        return
    if auth.authorization_header(request) is None:
        abort(401)
    if auth.current_user(request) is None:
        abort(403)


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found handler"""
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Unauthorized handler"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """Forbidden handler"""
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
