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
        if not path or not excluded_paths or not len(excluded_paths):
            return True

        if path[-1] != "/":
            path += "/"

        for exc_path in excluded_paths:
            if exc_path[-1] != "/":
                exc_path += "/"

            if exc_path[-2] == "*":
                splited_exc_path = exc_path.split("/")[-2]
                exc_path_end = splited_exc_path.split("*")[-2]
                return not path.__contains__(exc_path_end)

        if path in excluded_paths:
            return False

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
