#!/usr/bin/env python3


"""
Class that provides authentication and authorization functionality
"""

from typing import List, TypeVar

from flask import request


class Auth:
    """
    This class provides authentication and authorization functionality.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for the given path
        """
        if path and excluded_paths:
            if path[-1] != "/":
                path += "/"

            for exc_path in excluded_paths:
                if exc_path[-1] != "/":
                    exc_path += "/"

            if path in excluded_paths:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.
        """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """
        Retrieves the current user from the request.
        """
        return None
