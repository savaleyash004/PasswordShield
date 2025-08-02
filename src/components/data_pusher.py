"""
Module for data pushing functionality.
"""
import sys

import opendatasets as od
import pandas as pd
from pymongo import MongoClient

from src.interface.config import FilePathConfig, MongoDBConfig
from src.middleware.exception import CustomException
from src.middleware.logger import logger
from src.utils.data_validation import is_valid_password
from src.utils.feature_extraction import calculate_strength


class DataPusher:
    """
    Class for data pushing operations.
    """

    def __init__(self) -> None:
        """
        Initializes the DataPusher class.
        """
        self.mongodb_config = MongoDBConfig()
        self.filepath_config = FilePathConfig()

    def initiate_data_push(
        self, sample_size: int = 2500, num_bins: int = 10
    ) -> pd.DataFrame:
        """Perform the data pushing process.

        Args:
            sample_size (int, optional): Size of the sample for each bin. Defaults to 2500.
            num_bins (int, optional): Total number of bins. Defaults to 10.

        Raises:
            CustomException: Catches error

        Returns:
            pd.DataFrame: Clean & Filtered dataset
        """
        try:
            logger.info("Started data push method")

            logger.info("Started downloading data")
            od.download(
                self.filepath_config.database_url,
            )
            logger.info("Done downloading data")

            logger.info("Started fetching data")
            data_frame = pd.read_csv(
                self.filepath_config.raw_data_path,
                header=None,
                names=["password"],
                sep="\t",
                encoding="ISO-8859-1",
            )
            logger.info("Done fetching data")

            logger.info("Started removing duplicates")
            data_frame = data_frame.dropna()
            logger.info("Done removing duplicates")

            logger.info("Started cleaning data")
            data_frame["IsValid"] = data_frame["password"].apply(
                is_valid_password
            )
            df1 = data_frame[data_frame["IsValid"] == 1]
            df1 = df1.drop(["IsValid"], axis=1)
            logger.info("Done cleaning data")

            logger.info("Started creating target data")
            df1["strength"] = df1["password"].apply(calculate_strength)
            logger.info("Done creating target data")

            logger.info("Start balancing data")

            df1["bin"] = pd.cut(df1["strength"], num_bins, labels=False)
            sample_df = df1.groupby("bin", group_keys=False).apply(
                lambda x: x.sample(min(len(x), sample_size), random_state=24)
            )
            sample_df.drop(["bin"], axis=1, inplace=True)
            logger.info("Data balancing data")

            logger.info("Done clean & filtered dataset")
            return sample_df

        except Exception as error:
            raise CustomException(error, sys) from error

    def push_to_mongodb(
        self, data_frame: pd.DataFrame, chunk_size: int = 1000
    ) -> None:
        """Push the data to MongoDB.

        Args:
            data_frame (pd.DataFrame): Input DataFrame
            chunk_size (int, optional): Amount of chunks to send.
            Defaults to 10_00_000.

        Raises:
            CustomException: Catches error
        """
        try:
            logger.info("Started connected to MongoDB")
            client = MongoClient(self.mongodb_config.mongodb_connection_string)
            database = client[self.mongodb_config.database_name]
            collection = database[self.mongodb_config.collection_name]
            logger.info("Done connected to MongoDB")

            total_rows = data_frame.shape[0]
            num_chunks = total_rows // chunk_size

            logger.info("Started insert data into MongoDB")
            for chunk in range(num_chunks):
                start = chunk * chunk_size
                end = min(start + chunk_size, total_rows)
                chunk_data = data_frame.iloc[start:end].to_dict(
                    orient="records"
                )
                collection.insert_many(chunk_data)

                logger.info(
                    "Chunk %s/%s inserted into MongoDB",
                    chunk + 1,
                    num_chunks,
                )

            self._close_db("Done insert data into MongoDB", client)
        except Exception as error:
            raise CustomException(error, sys) from error

    def get_data_from_mongodb(self, chunk_size: int = 1000) -> pd.DataFrame:
        """Retrieve data from MongoDB.

        Args:
            chunk_size (int, optional): Amount of chunks to retrieve.
            Defaults to 10_00_000.

        Raises:
            CustomException: Catches error

        Returns:
            pd.DataFrame: Dataset in df
        """
        try:
            logger.info("Started connected to MongoDB")
            client = MongoClient(self.mongodb_config.mongodb_connection_string)
            database = client[self.mongodb_config.database_name]
            collection = database[self.mongodb_config.collection_name]
            logger.info("Done connected to MongoDB")

            total_documents = collection.count_documents({})
            num_chunks = total_documents // chunk_size

            data_frame = pd.DataFrame()

            logger.info("Started fetch data from MongoDB")
            for chunk in range(num_chunks):
                skip_documents = chunk * chunk_size
                chunk_data = list(
                    collection.find(
                        {},
                        {"_id": 0},  # Exclude the _id field
                        skip=skip_documents,
                        limit=chunk_size,
                    )
                )
                chunk_df = pd.DataFrame(chunk_data)
                data_frame = pd.concat(
                    [data_frame, chunk_df], ignore_index=True
                )

                logger.info(
                    "Fetched Chunk %s/%s from MongoDB", chunk + 1, num_chunks
                )

            self._close_db("Done fetch data from MongoDB", client)
            logger.info("Data retrieved from MongoDB")

            return data_frame

        except Exception as error:
            raise CustomException(error, sys) from error

    def _close_db(self, message: str, client: MongoClient) -> None:
        """Closing MongoDB client

        Args:
            message (str): Log info message
            client (MongoClient): MongoClient object
        """
        logger.info(message)
        logger.info("Started close MongoDB")
        client.close()
        logger.info("Done close MongoDB")


if __name__ == "__main__":
    data_pusher = DataPusher()
    df = data_pusher.initiate_data_push()
    data_pusher.push_to_mongodb(df)
    df2 = data_pusher.get_data_from_mongodb()
    logger.debug(df2.info())
