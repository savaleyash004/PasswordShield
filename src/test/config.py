"""
This module contains mock configuration classes for file paths and MongoDB
settings, used for testing purposes.
"""
import os
from dataclasses import dataclass

from src.interface.config import FilePathConfig, MongoDBConfig


# Mock the necessary dependencies
@dataclass
class MockMongoDBConfig(MongoDBConfig):
    """Mock configuration class for MongoDB."""

    mongodb_connection_string: str = "mongodb://localhost:27017/"
    database_name: str = "PassShield"
    collection_name: str = "sample"


@dataclass
class MockFilePathConfig(FilePathConfig):
    """Configuration class for file paths."""

    database_url: str = "https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt"
    raw_data_path: str = os.path.join(
        "common-password-list-rockyoutxt", "rockyou.txt"
    )
    train_data_path: str = os.path.join("sample_artifacts", "train.csv")
    test_data_path: str = os.path.join("sample_artifacts", "test.csv")
    preprocessor_path: str = os.path.join(
        "sample_artifacts", "preprocessor.pkl"
    )
    model_path: str = os.path.join("sample_artifacts", "model.pkl")
