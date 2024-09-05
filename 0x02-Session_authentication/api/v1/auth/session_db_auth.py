#!/usr/bin/env python3

"""SessionDBAuth class"""

from datetime import datetime, timedelta

from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """SessionDBAuth class"""

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session for the specified user.

        Args:
          user_id (str, optional): The ID of the user. Defaults to None.

        Returns:
          str: The session ID.
        """
        if not user_id or not isinstance(user_id, str):
            return None

        session_id = super().create_session(user_id)

        session_dictionary = {"user_id": user_id, "session_id": session_id}
        user_session = UserSession(**session_dictionary)

        user_session.save()
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieves the user ID associated with a given session ID.

        Args:
          session_id (str): The session ID to retrieve the user ID for.

        Returns:
          str: The user ID associated with the session ID.
        """
        try:
            sessions_list = UserSession.search({"session_id": session_id})
        except Exception:
            return None

        if not sessions_list or not len(sessions_list):
            return None

        curr_time = datetime.now()
        session_dur = timedelta(seconds=self.session_duration)
        session_exp = sessions_list[0].created_at + session_dur
        if session_exp < curr_time:
            return None

        return sessions_list[0].user_id

    def destroy_session(self, request=None):
        """
        Destroy a session.

        Args:
          request (Request): The request object. Defaults to None.

        Returns:
          None
        """
        if not request:
            return False

        session_id = self.session_cookie(request)

        if not session_id:
            return False

        sessions_list = UserSession.search({"session_id": session_id})

        if not sessions_list or not len(sessions_list):
            return False

        sessions_list[0].remove()
        return True
