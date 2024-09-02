#!/usr/bin/env python3

"""Basic auth"""

import base64

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

    def decode_base64_authorization_header(self, b64_auth_header: str) -> str:
        """
        Decode a base64 encoded authorization header.

        Args:
          b64_auth_header (str): The base64 encoded authorization header.

        Returns:
          str: The decoded authorization header as a string,
          or None if decoding fails.
        """

        if not b64_auth_header or not isinstance(b64_auth_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(b64_auth_header)
            return decoded_bytes.decode("utf-8")
        except Exception:
            return None
