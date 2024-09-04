#!/usr/bin/env python3
""" Module of SessionAuth views
"""

from os import getenv

from flask import abort, jsonify, request

from api.v1.views import app_views
from models.user import User


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def auth_login() -> str:
    """
    Authenticates a user login by checking the provided email and password.

    Returns:
      str: JSON response containing user information if login is successful.

    Raises:
      400: If email or password is missing.
      404: If no user is found for the provided email.
      401: If the password is incorrect.
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not len(email):
        return jsonify({"error": "email missing"}), 400
    if not password or not len(password):
        return jsonify({"error": "password missing"}), 400

    users_list = User.search({"email": email})

    if not users_list or not len(users_list):
        return jsonify({"error": "no user found for this email"}), 404

    for user in users_list:
        if not user.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

        from api.v1.app import auth

        session_id = auth.create_session(user.id)
        res = jsonify(user.to_json())
        cookies = getenv("SESSION_NAME")
        res.set_cookie(cookies, session_id)

        return res
