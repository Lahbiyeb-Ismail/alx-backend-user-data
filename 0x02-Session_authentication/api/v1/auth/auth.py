#!/usr/bin/env python3


"""
Class that provides authentication and authorization functionality
"""

from os import getenv
from typing import List, TypeVar

from flask import request

SESSION_NAME = getenv("SESSION_NAME")


class Auth:
    """
    This class provides authentication and authorization functionality.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for the given path
        """
        if not path or not excluded_paths or not len(excluded_paths):
            return True

        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif (
                path == excluded_path
                or path == excluded_path.rstrip("/")
                or "".join([path, "/"]) == excluded_path
            ):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.
        """
        if request is None:
            return None

        auth_header = request.headers.get("Authorization")

        if auth_header is None:
            return None

        return auth_header

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """
        Retrieves the current user from the request.
        """
        return None

    def session_cookie(self, request=None):
        """
        Retrieves the session cookie from the request.

        Args:
            request (Request): The request object.

        Returns:
            str: The value of the session cookie, or None if
            the request is None.
        """

        if request is None:
            return None

        session_cookie = request.cookies.get(SESSION_NAME)
        return session_cookie
