#!/usr/bin/env python3

"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """DB class"""

    def __init__(self) -> None:
        """Initialize a new DB instance"""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Add a new user to the database.

        Args:
          email (str): The email of the user.
          hashed_password (str): The hashed password of the user.

        Returns:
          User: The newly created User object.
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments"""
        # try:
        #     user = self._session.query(User).filter_by(**kwargs).one()
        # except NoResultFound:
        #     raise NoResultFound()
        # except InvalidRequestError:
        #     raise InvalidRequestError()
        # return user

        if not kwargs:
            raise InvalidRequestError

        user = self._session.query(User).filter_by(**kwargs).first()

        if not user:
            raise NoResultFound

        return user

    def update_user(self, user_id, **kwargs) -> None:
        """
        Update the user with the given user_id using
        the provided keyword arguments.

        Args:
          user_id (int): The ID of the user to be updated.
          **kwargs: Keyword arguments representing the
          fields to be updated and their new values.

        Raises:
          ValueError: If the provided field name does not
          exist in the user object.

        Returns:
          None
        """
        if not user_id:
            return

        user = self.find_user_by(id=user_id)

        for key, val in kwargs.items():
            if not hasattr(user, key):
                raise ValueError()

            setattr(user, key, val)

        self._session.commit()
        return None
