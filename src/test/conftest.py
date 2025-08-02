"""
This module contains test fixtures for the unit tests of the data ingestion
and data pusher components.
"""
import pytest

from src.components.data_ingestion import DataIngestion
from src.components.data_pusher import DataPusher
from src.components.data_transformation import DataTransformation
from src.components.model_trainer import ModelTrainer
from src.interface.config import CustomData
from src.pipe.pipeline import Pipeline
from src.test.config import MockFilePathConfig, MockMongoDBConfig


@pytest.fixture(scope="session", name="data_pusher")  # type: ignore
def data_pusher_fixture() -> DataPusher:
    """Fixture for creating a DataPusher instance with mock configurations.

    Returns:
        DataPusher: The DataPusher instance.
    """
    data_pusher = DataPusher()
    data_pusher.mongodb_config = MockMongoDBConfig()
    data_pusher.filepath_config = MockFilePathConfig()
    return data_pusher


@pytest.fixture(scope="session", name="data_ingestion")  # type: ignore
def data_ingestion_fixture() -> DataIngestion:
    """
    Fixture to create a DataIngestion object before each test.

    Returns:
        DataIngestion: An instance of the DataIngestion class.
    """
    data_ingestion = DataIngestion()
    data_ingestion.filepath_config = MockFilePathConfig()
    return data_ingestion


@pytest.fixture(scope="session", name="data_transformation")  # type: ignore
def data_transformation_fixture() -> DataTransformation:
    """Fixture to create a DataTransformation object before each test.

    Returns:
        DataTransformation: An instance of the DataTransformation class.
    """
    data_transformation = DataTransformation()
    data_transformation.filepath_config = MockFilePathConfig()
    return data_transformation


@pytest.fixture(scope="session", name="model_trainer")  # type: ignore
def model_trainer_fixture() -> ModelTrainer:
    """Fixture to create a ModelTrainer object before each test.

    Returns:
        ModelTrainer: An instance of the ModelTrainer class.
    """
    model_trainer = ModelTrainer()
    model_trainer.filepath_config = MockFilePathConfig()
    return model_trainer


@pytest.fixture(scope="session", name="pipeline")  # type: ignore
def pipeline_fixture() -> Pipeline:
    """Fixture to create a Pipeline object before each test.

    Returns:
        Pipeline: An instance of the Pipeline class.
    """
    pipeline = Pipeline()
    pipeline.filepath_config = MockFilePathConfig()
    pipeline.data_pusher.mongodb_config = MockMongoDBConfig()
    pipeline.data_pusher.mongodb_config.collection_name = "test_sample"
    return pipeline


@pytest.fixture(scope="session", name="custom_data")  # type: ignore
def custom_data_fixture() -> CustomData:
    """Fixture to create a CustomData object before each test.

    Returns:
        CustomData: An instance of the CustomData class.
    """
    return CustomData()


@pytest.fixture(scope="session", name="valid_password")  # type: ignore
def valid_password_fixture() -> str:
    """Fixture to create a valid_password object before each test.

    Returns:
        str: An instance of the valid_password string.
    """
    return "^StrOngP@ssw0rd1toB!SD3r#$nHhcs"


@pytest.fixture(scope="session", name="invalid_short_password")  # type: ignore
def invalid_short_password_fixture() -> str:
    """Fixture to create a invalid_short_password object before each test.

    Returns:
        str: An instance of the invalid_short_password string.
    """
    return "bad"


@pytest.fixture(scope="session", name="invalid_characters_password")  # type: ignore
def invalid_characters_password_fixture() -> str:
    """Fixture to create a invalid_characters_password object before each test.

    Returns:
        str: An instance of the invalid_characters_password string.
    """
    return "invalid@password?"


@pytest.fixture(scope="session", name="invalid_long_password")  # type: ignore
def invalid_long_password_fixture() -> str:
    """Fixture to create a invalid_long_password object before each test.

    Returns:
        str: An instance of the invalid_long_password string.
    """
    return "ux$zzSj4r66Wd4&2%PC^SgFI5@ghY1NWvD**LC72AJt!4G^$epIq6TxKgbMJLPmfJ3@2la"
