#!/usr/bin/env python3

"""Basic auth"""

import base64
from typing import Tuple, TypeVar

from api.v1.auth.auth import Auth
from models.user import User


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

    def extract_user_credentials(self, decAuth_header: str) -> Tuple[str, str]:
        """
        Extracts the user credentials from the decoded Authorization header.

        Args:
          decAuth_header (str): The decoded Authorization header.

        Returns:
          Tuple[str, str]: A tuple containing the email
          and password extracted from the header.

        Raises:
          None

        """

        if (
            not decAuth_header
            or not isinstance(decAuth_header, str)
            or not decAuth_header.__contains__(":")
        ):
            return None, None

        email = decAuth_header.split(":")[0]
        password = decAuth_header.split(":")[1]

        return email, password

    def user_object_from_credentials(
        self, email: str, pwd: str
    ) -> TypeVar("User"):  # type: ignore
        """
        Retrieve a user object based on the provided email
        and password credentials.

        Args:
          user_email (str): The email of the user.
          user_pwd (str): The password of the user.

        Returns:
          User: The user object if the credentials are valid, otherwise None.
        """
        if not email or not isinstance(email, str):
            return None
        if not pwd or not isinstance(pwd, str):
            return None

        try:
            users = User.search({"email": email})
            if not users:
                return None

            for user in users:
                if user.is_valid_password(pwd):
                    return user
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar("User"):  # type: ignore
        """
        Retrieves the current user based on the provided request.

        Args:
          request (Optional[Request]): The request object (default: None).

        Returns:
          User: The user object corresponding to the provided credentials.

        """
        auth_header = self.authorization_header(request)
        if not auth_header:
            return

        b64_auth = self.extract_base64_authorization_header(auth_header)
        dec_auth = self.decode_base64_authorization_header(b64_auth)
        email, password = self.extract_user_credentials(dec_auth)
        user = self.user_object_from_credentials(email, password)

        return user
