"""This module provides functions for saving and loading objects using joblib."""

import os
import sys
from typing import Any

import joblib

from src.middleware.exception import CustomException


def save_object(file_path: str, obj: Any) -> None:
    """Save an object to a file using joblib.

    Args:
        file_path (str): The path of the file to save the object to.
        obj (Any): The object to be saved.

    Raises:
        CustomException: If there is an error while saving the object.
    """
    try:
        dir_path = os.path.dirname(file_path)
        os.makedirs(dir_path, exist_ok=True)
        joblib.dump(obj, file_path)

    except Exception as error:
        raise CustomException(error, sys) from error


def load_object(file_path: str) -> Any:
    """Load an object from a file using joblib.

    Args:
        file_path (str): The path of the file to load the object from.

    Raises:
        CustomException: If there is an error while loading the object.

    Returns:
        Any: The loaded object.
    """
    try:
        return joblib.load(file_path)

    except Exception as error:
        raise CustomException(error, sys) from error
