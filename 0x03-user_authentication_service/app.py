#!/usr/bin/env python3

"""
basic Flask app set up
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def home_route():
    """
    Returns a JSON response with a welcome message.
    """
    return jsonify({"message": "Bienvennue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
