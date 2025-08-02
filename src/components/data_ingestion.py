"""
This module handles the data ingestion process by fetching data from
MongoDB, performing train-test split, and saving the split data
as CSV files.
"""
import os
import sys
from typing import Any

import pandas as pd
from sklearn.model_selection import train_test_split

from src.components.data_pusher import DataPusher
from src.interface.config import FilePathConfig
from src.middleware.exception import CustomException
from src.middleware.logger import logger


class DataIngestion:
    """
    This class handles the data ingestion process.

    Methods:
        __init__(): Initializes the DataIngestion class.
        initiate_data_ingestion(): Initiates the data ingestion process.
        data_report(): Generates a report on the ingested data.
        _display_report(): Displays a report.

    Attributes:
        filepath_config (FilePathConfig): An instance of FilePathConfig
        class for managing file paths.
    """

    def __init__(self) -> None:
        """
        Initializes the DataIngestion class.
        """
        self.filepath_config = FilePathConfig()

    def initiate_data_ingestion(self, data_frame: pd.DataFrame) -> Any:
        """Initiates the data ingestion process.

        Args:
            data_frame (pd.DataFrame): Dataframe got form mongoDB

        Raises:
            CustomException: Raised when an error occurs
            during data ingestion.

        Returns:
            Any: A tuple containing the file paths of
            the train and test data.
        """
        try:
            logger.info("Started data ingestion method")

            logger.info("Train test split initiated")
            os.makedirs(
                os.path.dirname(self.filepath_config.train_data_path),
                exist_ok=True,
            )
            train_set, test_set = train_test_split(
                data_frame, test_size=0.2, random_state=42
            )
            logger.info("Done Train test split")

            logger.info("Saving Train test split")
            train_set.to_csv(
                self.filepath_config.train_data_path, index=False, header=True
            )
            test_set.to_csv(
                self.filepath_config.test_data_path, index=False, header=True
            )
            logger.info("Finish saving Train test split")

            logger.info("Data ingestion completed")

            return (
                self.filepath_config.train_data_path,
                self.filepath_config.test_data_path,
            )

        except Exception as error:
            raise CustomException(error, sys) from error

    def data_report(self) -> None:
        """
        Generates a report on the ingested data.
        """
        try:
            logger.info("Generating data report")

            train_df = pd.read_csv(self.filepath_config.train_data_path)
            test_df = pd.read_csv(self.filepath_config.test_data_path)

            self._display_report("Train dataset:", train_df.head())
            self._display_report("Test dataset:", test_df.head())

            self._display_report(
                "Train dataset statistics:", train_df.describe()
            )
            self._display_report(
                "Test dataset statistics:", test_df.describe()
            )

            self._display_report("Train dataset info:", train_df.info())
            self._display_report("Test dataset info:", test_df.info())

            self._display_report(
                "Train dataset strength destitution:",
                train_df["strength"].value_counts(bins=5),
            )
            self._display_report(
                "Test dataset strength destitution:",
                test_df["strength"].value_counts(bins=5),
            )

        except Exception as error:
            raise CustomException(error, sys) from error

    def _display_report(self, arg0: str, arg1: Any) -> None:
        """
        Displays a report.

        Args:
            arg0 (str): A description of the report.
            arg1 (Any): The content of the report.
        """
        logger.info(arg0)
        logger.info(arg1)
        logger.info("Done %s", arg0)


if __name__ == "__main__":
    obj = DataIngestion()
    obj.filepath_config.train_data_path = "src/test/data/train.csv"
    obj.filepath_config.test_data_path = "src/test/data/test.csv"
    dataframe = DataPusher().get_data_from_mongodb()
    obj.initiate_data_ingestion(dataframe)
