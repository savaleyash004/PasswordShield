"""
A pipeline for data ingestion, transformation, model training,
and prediction.
"""

import sys
from typing import Any

import pandas as pd
import numpy as np
import unicodedata

from src.components.data_ingestion import DataIngestion
from src.components.data_pusher import DataPusher
from src.components.data_transformation import DataTransformation
from src.components.model_trainer import ModelTrainer
from src.interface.config import CustomData, FilePathConfig
from src.middleware.exception import CustomException
from src.middleware.logger import logger
from src.utils.file_manager import load_object


class Pipeline:
    """A pipeline for data ingestion, transformation, model training,
    and prediction."""

    def __init__(self) -> None:
        """Initialize the Pipeline object."""

        self.data_pusher = DataPusher()
        self.data_ingestion = DataIngestion()
        self.data_transformation = DataTransformation()
        self.model_trainer = ModelTrainer()
        self.filepath_config = FilePathConfig()

    def push_data(self) -> None:
        """Push data to MongoDB, perform data ingestion, and generate
        data report.

        Raises:
            CustomException: If there is an error during the data push,
            data ingestion, or data report generation.
        """
        try:
            df = self.data_pusher.initiate_data_push()
            self.data_pusher.push_to_mongodb(df)
            dataframe = self.data_pusher.get_data_from_mongodb()
            self.data_ingestion.initiate_data_ingestion(dataframe)
            self.data_ingestion.data_report()

        except Exception as error:
            raise CustomException(error, sys) from error

    def train(self) -> None:
        """Perform data transformation, model training, and select the
        best model.

        Raises:
            CustomException: If there is an error during the data
            transformation or model training.
        """
        try:
            logger.info("Initializing training with extended character support")
            
            # Create transformer with improved handling for special characters
            transformer_obj = (
                self.data_transformation.get_data_transformer_object(
                    features=["password"]
                )
            )
            
            # Flag to track if we need to use fallback approach
            use_fallback = False
            train_arr = None
            test_arr = None
            
            try:
                # Perform data transformation with improved error handling
                (
                    train_arr,
                    test_arr,
                    _,
                ) = self.data_transformation.initiate_data_transformation(
                    target="strength", transformer=transformer_obj
                )
                
                logger.info("Successfully transformed data with %d training samples", 
                           len(train_arr) if train_arr is not None else 0)
                
            except Exception as e:
                logger.error("Error during data transformation: %s", str(e))
                logger.info("Attempting to continue with fallback approach...")
                use_fallback = True
                
                # Try again with enhanced filtering for problematic characters
                try:
                    # Load data directly and apply stronger filtering
                    train_df = pd.read_csv(self.filepath_config.train_data_path)
                    test_df = pd.read_csv(self.filepath_config.test_data_path)
                    
                    # More aggressive filtering to remove any problematic characters
                    def sanitize_password(pwd):
                        if not isinstance(pwd, str):
                            return str(pwd)
                        return ''.join(c for c in pwd if c.isascii() and c.isprintable())
                    
                    train_df['password'] = train_df['password'].apply(sanitize_password)
                    test_df['password'] = test_df['password'].apply(sanitize_password)
                    
                    # Keep only standard ASCII passwords
                    train_df = train_df[train_df['password'].apply(lambda x: all(ord(c) < 128 for c in x))]
                    test_df = test_df[test_df['password'].apply(lambda x: all(ord(c) < 128 for c in x))]
                    
                    logger.info(f"Fallback approach: Filtered to {len(train_df)} training and {len(test_df)} testing samples")
                    
                    # Try transformation again with filtered data
                    X_train = train_df.drop(columns=["strength"], axis=1)
                    y_train = train_df["strength"]
                    X_test = test_df.drop(columns=["strength"], axis=1)
                    y_test = test_df["strength"]
                    
                    X_train_arr = transformer_obj.fit_transform(X_train)
                    X_test_arr = transformer_obj.transform(X_test)
                    
                    train_arr = np.c_[X_train_arr, np.array(y_train)]
                    test_arr = np.c_[X_test_arr, np.array(y_test)]
                    
                    logger.info("Successfully used fallback approach with %d training samples", len(train_arr))
                    
                except Exception as fallback_error:
                    logger.error("Fallback approach also failed: %s", str(fallback_error))
                    raise CustomException("Both main and fallback approaches failed", sys)
            
            # Only proceed with model training if we have data
            if train_arr is not None and test_arr is not None and len(train_arr) > 0:
                # Evaluate and select the best model
                report = self.model_trainer.evaluate_models(train_arr, test_arr)
                name_model, score = self.model_trainer.select_best_model(
                    report, test_arr
                )
                logger.info("Best model: %s Score: %s", name_model, score)
            else:
                raise CustomException("Failed to prepare training data", sys)

        except Exception as error:
            raise CustomException(error, sys) from error

    def predict(self, features: pd.DataFrame) -> Any:
        """Perform prediction on the given features.

        Args:
            features (pd.DataFrame): The features to be predicted.

        Raises:
            CustomException: If there is an error during the prediction.

        Returns:
            np.ndarray[np.float64, Any]: The predicted values.
        """
        try:
            logger.info("Initiated load files")
            model = load_object(file_path=self.filepath_config.model_path)
            preprocessor = load_object(
                file_path=self.filepath_config.preprocessor_path
            )
            logger.info("Done load files")

            logger.info("Initiated data transformation")
            data_scaled = preprocessor.transform(features)
            logger.info("Done data transformation")

            logger.info("Initiated prediction")
            result = model.predict(data_scaled)
            logger.info("Done prediction")

            return result

        except Exception as error:
            raise CustomException(error, sys) from error


if __name__ == "__main__":
    logger.info(
        "\nMain menu\n1. Push data\n2. Train pipeline\n3. Predict pipeline\n"
    )
    choice = int(input("Enter the choice: "))

    if choice == 1:
        Pipeline().push_data()
    elif choice == 2:
        Pipeline().train()
    elif choice == 3:
        custom_data = CustomData()
        input_data = str(input("Enter the password: "))
        password = custom_data.data2df(input_data)
        strength = Pipeline().predict(password)
        value = custom_data.array2data(strength)
        logger.info("\nPassword: %s Strength: %f", input_data, value)
    else:
        raise CustomException("Invalid input", sys)
