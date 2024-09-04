#!/usr/bin/env python3

"""Session auth class"""

from uuid import uuid4

from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """Session auth class"""

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session for the given user ID.

        Args:
          user_id (str): The ID of the user.

        Returns:
          str: The session ID.

        """
        if not user_id or not isinstance(user_id, str):
            return None

        session_id = str(uuid4())

        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieves the user ID associated with the given session ID.

        Args:
          session_id (str): The session ID to retrieve the user ID for.

        Returns:
          str: The user ID associated with the session ID,
          or None if the session ID is invalid or not provided.
        """

        if not session_id or not isinstance(session_id, str):
            return None

        user_id = self.user_id_by_session_id.get(session_id)
        return user_id

    def current_user(self, request=None):
        """
        Retrieves the current user based on the session cookie.

        Args:
          request (Request): The request object (default: None).

        Returns:
          User: The current user object.

        """

        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)

        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """
        Destroy a session.

        Args:
          request (Request): The request object (default: None).

        Returns:
          bool: True if the session is successfully destroyed, False otherwise.
        """
        if not request or not self.session_cookie(request):
            return False

        session_cookie = self.session_cookie(request)

        if not session_cookie:
            return False

        if not self.user_id_for_session_id(session_cookie):
            return False

        del self.user_id_by_session_id[session_cookie]

        return True
