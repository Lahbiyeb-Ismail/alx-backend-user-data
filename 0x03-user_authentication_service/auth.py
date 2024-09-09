#!/usr/bin/env python3

import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Hashes the given password using bcrypt algorithm.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.

    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
