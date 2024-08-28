#!/usr/bin/env python3


"""
0x00. Personal data Tasks
"""

import logging
import re
from os import environ
from typing import List

import mysql.connector

# def filter_datum(
#     fields: List[str], redaction: str, message: str, separator: str
# ) -> str:
#     """
#     Filter sensitive data from a message based on specified fields.

#     Args:
#       fields (List[str]): A list of fields to filter.
#       redaction (str): The string to replace the filtered data with.
#       message (str): The message containing the data to be filtered.
#       separator (str): The separator used to split the message
#       into data segments.

#     Returns:
#       str: The filtered message with sensitive data replaced.

#     """
# user_data = message.split(separator)
# for i in range(len(user_data)):
#     for field in fields:
#         if field in user_data[i]:
#             user_data[i] = re.sub(
#                 user_data[i].split("=")[1], redaction, user_data[i]
#             )
# return separator.join(user_data)

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """
    Filter sensitive data from a message based on specified fields.

    Args:
      fields (List[str]): A list of fields to filter.
      redaction (str): The string to replace the filtered data with.
      message (str): The message containing the data to be filtered.
      separator (str): The separator used to split the message
      into data segments.

    Returns:
      str: The filtered message with sensitive data replaced.

    """
    for f in fields:
        field = f"{f}=.*?{separator}"
        message = re.sub(field, f"{f}={redaction}{separator}", message)

    return message


def get_logger() -> logging.Logger:
    """
    Returns a logger object configured to log user data.

    Returns:
        logging.Logger: The logger object configured to log user data.
    """

    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))

    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Retrieves a connection to the personal data database.

    Returns:
        mysql.connector.connection.MySQLConnection:
        A connection to the personal data database.
    """

    user = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    database = environ.get("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connection.MySQLConnection(
        user=user, password=password, host=host, database=database
    )


def main() -> None:
    """
    Retrieves user data from the database and logs it using the info_logger.

    This function performs the following steps:
    1. Defines the fields to retrieve from the database.
    2. Splits the fields into a list of columns.
    3. Constructs a SQL query to select the specified fields
    from the 'users' table.
    4. Retrieves the info_logger.
    5. Retrieves the database connection.
    6. Executes the query and fetches all rows from the result.
    7. Iterates over each row and constructs a log message.
    8. Creates a log record using the log message and logs
    it using the info_logger.

    Parameters:
    None

    Returns:
    None
    """

    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(",")

    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()

    connection = get_db()

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: "{}={}".format(x[0], x[1]),
                zip(columns, row),
            )
            msg = "{};".format("; ".join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats the log record message by filtering sensitive data.
        """
        record.msg = filter_datum(
            self.fields, self.REDACTION, record.msg, self.SEPARATOR
        )
        return super().format(record)


if __name__ == "__main__":
    main()
