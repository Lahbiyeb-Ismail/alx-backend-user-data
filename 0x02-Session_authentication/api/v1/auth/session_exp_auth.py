#!/usr/bin/env python3

"""Session auth with expiration date for the sessionId"""


from datetime import datetime, timedelta
from os import getenv

from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session auth with expiration date for the sessionId"""

    def __init__(self) -> None:
        """
        Initializes a SessionExpAuth object.
        """
        super().__init__()
        try:
            self.session_duration = int(getenv("SESSION_DURATION"))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session for the given user ID.

        Args:
          user_id (str, optional): The ID of the user. Defaults to None.

        Returns:
          str: The session ID.

        """
        session_id = super().create_session(user_id)

        if not session_id:
            return None

        self.user_id_by_session_id[session_id] = {
            "user_id": user_id,
            "created_at": datetime.now(),
        }

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieve the user ID associated with the given session ID.

        Args:
          session_id (str): The session ID to retrieve the user ID for.

        Returns:
          str: The user ID associated with the session ID,
          or None if the session ID is invalid or expired.
        """
        if session_id in self.user_id_by_session_id:
            session_dict = self.user_id_by_session_id[session_id]

            if self.session_duration <= 0:
                return session_dict["user_id"]

            if "created_at" not in session_dict:
                return None

            curr_time = datetime.now()
            time_range = timedelta(seconds=self.session_duration)
            session_exp = session_dict["created_at"] + time_range

            if session_exp < curr_time:
                return None

            return session_dict["user_id"]
