#!/usr/bin/env python3

"""SessionDBAuth class"""

from api.v1.auth.session_exp_auth import SessionExpAuth


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
        return super().create_session(user_id)

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieves the user ID associated with a given session ID.

        Args:
          session_id (str): The session ID to retrieve the user ID for.

        Returns:
          str: The user ID associated with the session ID.
        """
        return super().user_id_for_session_id(session_id)

    def destroy_session(self, request=None):
        """
        Destroy a session.

        Args:
          request (Request): The request object. Defaults to None.

        Returns:
          None
        """
        return super().destroy_session(request)
