#!/usr/bin/env python3

"""Auth Module"""

from typing import Union
from uuid import uuid4

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """
    Hashes the given password using bcrypt algorithm.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.

    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generates a UUID (Universally Unique Identifier) as a string.

    Returns:
        str: A string representation of the generated UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user with the given email and password.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            User: The newly registered user.

        Raises:
            ValueError: If a user with the given email already exists.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)

            return new_user

        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Check if the login credentials are valid for a given
        email and password.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the login credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return user and bcrypt.checkpw(
                password.encode("utf-8"), user.hashed_password
            )
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a session for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The session ID.

        Raises:
            NoResultFound: If no user with the given email is found.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()

            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Retrieves a user from the session ID.

        Args:
            session_id (str): The session ID of the user.

        Returns:
            Union[User, None]: The user object if found, None otherwise.
        """
        if not session_id:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy the session for the user with the given user ID.

        Args:
            user_id (int): The ID of the user.

        Returns:
            None
        """
        if not user_id:
            return None

        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a reset password token for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The generated reset password token.

        Raises:
            ValueError: If no user is found with the given email.
        """

        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()

            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the password for a user using the provided reset token.

        Args:
            reset_token (str): The reset token associated with the user.
            password (str): The new password to be set for the user.

        Raises:
            ValueError: If no user is found with the given reset token.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            new_hashed_pwd = _hash_password(password)
            self._db.update_user(
                user.id, hashed_password=new_hashed_pwd, reset_token=None
            )
            return None
        except NoResultFound:
            raise ValueError
