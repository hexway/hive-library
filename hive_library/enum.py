# Description
"""
Hive enums
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from enum import Enum


# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b1"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"


class ListEnum(Enum):
    @classmethod
    def list(cls):
        return list(map(lambda c: c.value, cls))


class PermissionTypes(str, ListEnum):
    EDIT = "EDIT"
    READONLY = "READONLY"
    OWNER = "OWNER"
    ADMIN = "ADMIN"


class RecordTypes(str, ListEnum):
    STRING = "string"
    TEXT_BLOCK = "text_block"
    NUMBER = "number"
    TUPLE = "tuple"
    CODEBLOCK = "codeblock"
    FILE = "file"
    LIST = "list"
    DIRECTORY = "directory"
    NESTED = "nested"


class TaskStates(str, ListEnum):
    SUCCESS = "SUCCESS"
    PROGRESS = "PROGRESS"
    PENDING = "PENDING"
    FAILURE = "FAILED"
    CANCELLED = "CANCELLED"
