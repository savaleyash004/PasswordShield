"""
Module for configuration classes related to file paths and MongoDB settings.
"""
import os
import sys
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
from dotenv import load_dotenv

from src.middleware.exception import CustomException

# Get the absolute path to the root directory of the project
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
ENV_PATH = os.path.join(ROOT_DIR, ".env")

# Load environment variables
print(f"Loading .env file from: {ENV_PATH}")
load_dotenv(ENV_PATH)

# Create config dictionary from environment
config = dict(os.environ)

# Debug: Print available environment variables (excluding sensitive values)
print("Available environment variables:")
for key in config:
    if 'KEY' not in key.upper() and 'SECRET' not in key.upper() and 'PASS' not in key.upper():
        print(f"- {key}")


class CustomData:
    """A class for handling custom data."""

    def data2df(self, password: str) -> pd.DataFrame:
        """Convert the given password into a pandas DataFrame.

        Args:
            password (str): The password to be converted.

        Raises:
            CustomException: If there is an error during the conversion.

        Returns:
            pd.DataFrame: The password converted into a pandas DataFrame.
        """
        try:
            input_data = {
                "password": [password],
            }

            return pd.DataFrame(input_data)

        except Exception as error:
            raise CustomException(error, sys) from error

    def array2data(self, arr: np.ndarray[np.float64, Any]) -> Any:
        """Convert the given NumPy array to a single value.

        Args:
            arr (np.ndarray): The NumPy array to be converted.

        Returns:
            float: The converted value.
        """
        try:
            return arr.item()

        except Exception as error:
            raise CustomException(error, sys) from error


@dataclass
class FilePathConfig:
    """Configuration class for file paths."""

    database_url: str = "https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt"
    raw_data_path: str = os.path.join(
        "common-password-list-rockyoutxt", "rockyou.txt"
    )
    train_data_path: str = os.path.join("artifacts", "train.csv")
    test_data_path: str = os.path.join("artifacts", "test.csv")
    preprocessor_path: str = os.path.join("artifacts", "preprocessor.pkl")
    model_path: str = os.path.join("artifacts", "model.pkl")


@dataclass
class MongoDBConfig:
    """Configuration class for MongoDB."""

    mongodb_connection_string: str = config.get("MONGODB_CONN_STRING", "mongodb://localhost:27017/")
    database_name: str = "PassShield"
    collection_name: str = "password_dataset"
