#!/usr/bin/env python3


"""
0x00. Personal data Tasks
"""

import logging
import re
from typing import List

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
