#!/usr/bin/env python3

"""Session auth class"""

from uuid import uuid4

from api.v1.auth.auth import Auth


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
