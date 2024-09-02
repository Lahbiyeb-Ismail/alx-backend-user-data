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
        return False

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.
        """
        return None

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """
        Retrieves the current user from the request.
        """
        return None
