#!/usr/bin/env python3

"""Basic auth"""

from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic auth"""

    def extract_base64_authorization_header(self, auth_header: str) -> str:
        """
        Extracts the base64 authorization header from the
        given authorization header.

        Args:
          auth_header (str): The authorization header to extract from.

        Returns:
          str: The extracted base64 authorization header.

        """
        if (
            not auth_header
            or not isinstance(auth_header, str)
            or not auth_header.startswith("Basic ")
        ):
            return None

        return auth_header.split("Basic ")[-1]
