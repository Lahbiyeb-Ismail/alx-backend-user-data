#!/usr/bin/env python3

"""
Encrypting passwords
"""

import bcrypt


def hash_password(password: str):
    """
    Hashes the given password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.

    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if a password is valid by comparing it with a hashed password.

    Args:
        hashed_password (bytes): The hashed password to compare against.
        password (str): The password to check.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
