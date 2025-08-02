"""
This module contains test cases for the DataIngestion class.
"""
import os

import pandas as pd
import pytest

from src.components.data_ingestion import DataIngestion
from src.components.data_pusher import DataPusher


def test_initiate_data_ingestion(
    data_ingestion: DataIngestion, data_pusher: DataPusher
) -> None:
    """
    Test the initiate_data_ingestion method of DataIngestion.

    Args:
        data_ingestion (DataIngestion): An instance of the DataIngestion class.
        data_pusher (DataPusher): An instance of the DataPusher class.
    """
    dataframe = data_pusher.get_data_from_mongodb()
    train_path, test_path = data_ingestion.initiate_data_ingestion(dataframe)
    assert os.path.exists(train_path)
    assert os.path.exists(test_path)


def test_data_report(
    data_ingestion: DataIngestion, data_pusher: DataPusher
) -> None:
    """
    Test the data_report method of DataIngestion.

    Args:
        data_ingestion (DataIngestion): An instance of the DataIngestion class.
        data_pusher (DataPusher): An instance of the DataPusher class.
    """
    dataframe = data_pusher.get_data_from_mongodb()
    _, _ = data_ingestion.initiate_data_ingestion(dataframe)
    data_ingestion.data_report()


def test_train_test_split_ratio(
    data_ingestion: DataIngestion, data_pusher: DataPusher
) -> None:
    """
    Test the train-test split ratio.

    Args:
        data_ingestion (DataIngestion): An instance of the DataIngestion class.
        data_pusher (DataPusher): An instance of the DataPusher class.
    """
    dataframe = data_pusher.get_data_from_mongodb()
    train_path, test_path = data_ingestion.initiate_data_ingestion(dataframe)
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    total_samples = len(train_df) + len(test_df)
    expected_train_ratio = len(train_df) / total_samples
    expected_test_ratio = len(test_df) / total_samples
    assert pytest.approx(expected_train_ratio, abs=0.02) == 0.8
    assert pytest.approx(expected_test_ratio, abs=0.02) == 0.2


def test_missing_values(
    data_ingestion: DataIngestion, data_pusher: DataPusher
) -> None:
    """
    Test for the absence of missing values in the train and test data.

    Args:
        data_ingestion (DataIngestion): An instance of the DataIngestion class.
        data_pusher (DataPusher): An instance of the DataPusher class.
    """
    dataframe = data_pusher.get_data_from_mongodb()
    train_path, test_path = data_ingestion.initiate_data_ingestion(dataframe)
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    assert not train_df.isnull().values.any()
    assert not test_df.isnull().values.any()


if __name__ == "__main__":
    pytest.main()
