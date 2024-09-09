#!/usr/bin/env python3

"""
basic Flask app set up
"""

from flask import Flask, abort, jsonify, make_response, redirect, request
from sqlalchemy.orm.exc import NoResultFound

from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", strict_slashes=False)
def home_route():
    """
    Returns a JSON response with a welcome message.
    """
    return jsonify({"message": "Bienvennue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users():
    """
    This function registers a new user by accepting the
    email and password from the request form.
    It calls the `register_user` function from the `AUTH`
    module to register the user.
    If the user is successfully registered, it returns a
    JSON response with the email and a success message.
    If the email is already registered, it returns a JSON
    response with an error message and a status code of 400.

    Returns:
      A JSON response containing the email and a success
      message if the user is successfully registered.
      A JSON response containing an error message and a status
      code of 400 if the email is already registered.
    """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """
    Logs in a user by validating the provided email and password.

    Returns:
      A response object containing the user's email and a success message.

    Raises:
      HTTPException: If the login credentials are invalid (status code 401).
    """

    email = request.form.get("email")
    password = request.form.get("password")

    is_valid_login = AUTH.valid_login(email, password)

    if not is_valid_login:
        abort(401)

    session_id = AUTH.create_session(email)
    response = make_response(jsonify({"email": email, "message": "logged in"}))
    response.set_cookie("session_id", session_id)

    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """
    Logs out the user by destroying the session associated
    with the user's session ID.

    Raises:
      NoResultFound: If the user cannot be found based on the session ID.

    Returns:
      None
    """

    session_id = request.cookies.get("session_id")

    try:
        user = AUTH.get_user_from_session_id(session_id)
        AUTH.destroy_session(user.user_id)
        redirect("/")
    except NoResultFound:
        abort(403)


@app.route("/profile", strict_slashes=False)
def profile():
    """
    Retrieves the user's profile information.

    Returns:
      A JSON response containing the user's email.

    Raises:
      HTTPException: If the user is not authenticated
      (403 Forbidden).
    """

    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    return jsonify({"email": user.email}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
