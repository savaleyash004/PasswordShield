"""
Test module for the DataPusher component.
"""

import pandas as pd
import pytest

from src.components.data_pusher import DataPusher


def test_initiate_data_push(data_pusher: DataPusher) -> None:
    """Test case for initiating the data push.

    Args:
        data_pusher (DataPusher): The DataPusher instance.
    """
    dataframe = data_pusher.initiate_data_push(500, 10)
    assert isinstance(dataframe, pd.DataFrame)
    assert dataframe.shape[0] > 0


def test_push_to_mongodb(data_pusher: DataPusher) -> None:
    """Test case for pushing data to MongoDB.

    Args:
        data_pusher (DataPusher): The DataPusher instance.
    """
    dataframe = data_pusher.initiate_data_push(500, 10)
    data_pusher.push_to_mongodb(dataframe)


def test_get_data_from_mongodb(data_pusher: DataPusher) -> None:
    """Test case for getting data from MongoDB.

    Args:
        data_pusher (DataPusher): The DataPusher instance.
    """
    dataframe = data_pusher.get_data_from_mongodb()
    assert isinstance(dataframe, pd.DataFrame)
    assert dataframe.shape[0] > 0


if __name__ == "__main__":
    pytest.main()
