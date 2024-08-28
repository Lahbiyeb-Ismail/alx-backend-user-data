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
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
