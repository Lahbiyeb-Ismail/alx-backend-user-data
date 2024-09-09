#!/usr/bin/env python3
"""
Main file
"""
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User

my_db = DB()

email = "test@test.com"
hashed_password = "hashedPwd"

user = my_db.add_user(email, hashed_password)
print(user.id)

try:
    my_db.update_user(user.id, hashed_password="NewPwd")
    print("Password updated")
except ValueError:
    print("Error")
