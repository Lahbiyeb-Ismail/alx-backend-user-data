#!/usr/bin/env python3

"""
User model
"""

from sqlalchemy import VARCHAR, Column, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """
    Represents a user model.

    Attributes:
      id (int): The unique identifier of the user.
      email (str): The email address of the user.
      hashed_password (str): The hashed password of the user.
      session_id (str): The session ID of the user.
      reset_token (str): The reset token of the user.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(VARCHAR(250), nullable=False)
    hashed_password = Column(VARCHAR(250), nullable=False)
    session_id = Column(VARCHAR(250), nullable=True)
    reset_token = Column(VARCHAR(250), nullable=True)
