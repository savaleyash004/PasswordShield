"""This module provides a class for data transformation and preprocessing."""

import sys
from typing import Any, List
import unicodedata

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer

from src.interface.config import FilePathConfig
from src.middleware.exception import CustomException
from src.middleware.logger import logger
from src.utils.feature_extraction import (
    AlphaLCTransform,
    AlphaUCTransform,
    ConsecAlphaLCTransform,
    ConsecAlphaUCTransform,
    ConsecNumberTransform,
    ConsecSymbolTransform,
    LenTransform,
    MidCharTransform,
    NonLatinTransform,
    NumberTransform,
    PatternTransform,
    RepCharTransform,
    SeqAlphaTransform,
    SeqKeyboardTransform,
    SeqNumberTransform,
    SymbolTransform,
    UniqueCharTransform,
)
from src.utils.file_manager import save_object


class DataTransformation:
    """A class for data transformation and preprocessing."""

    def __init__(self) -> None:
        """Initialize the DataTransformation object."""
        self.filepath_config = FilePathConfig()

    def get_data_transformer_object(
        self, features: List[str]
    ) -> ColumnTransformer:
        """Get a ColumnTransformer object for data transformation.

        Args:
            features (List[str]): List of feature names.

        Raises:
            CustomException: If there is an error during the transformation.

        Returns:
            ColumnTransformer: The ColumnTransformer object for data transformation.
        """
        try:
            logger.info("Initialize preprocess")

            preprocessor = ColumnTransformer(
                [
                    ("len", LenTransform(), features),
                    ("alpha_uc", AlphaUCTransform(), features),
                    ("alpha_lc", AlphaLCTransform(), features),
                    ("number", NumberTransform(), features),
                    ("symbol", SymbolTransform(), features),
                    ("mid_char", MidCharTransform(), features),
                    ("rep_char", RepCharTransform(), features),
                    ("unique_char", UniqueCharTransform(), features),
                    ("consec_alpha_uc", ConsecAlphaUCTransform(), features),
                    ("consec_alpha_lc", ConsecAlphaLCTransform(), features),
                    ("consec_number", ConsecNumberTransform(), features),
                    ("consec_symbol", ConsecSymbolTransform(), features),
                    ("seq_alpha", SeqAlphaTransform(), features),
                    ("seq_number", SeqNumberTransform(), features),
                    ("seq_keyboard", SeqKeyboardTransform(), features),
                    ("pattern", PatternTransform(), features),
                    ("non_latin", NonLatinTransform(), features),
                ]
            )
            logger.info("Complete preprocess")
            return preprocessor
        except Exception as error:
            raise CustomException(error, sys) from error

    def initiate_data_transformation(
        self, target: str, transformer: ColumnTransformer
    ) -> tuple[Any, Any, str]:
        """Initiate the data transformation process.

        Args:
            features (List[str]): List of feature names.
            target (str): The target variable name.

        Raises:
            CustomException: If there is an error during the data transformation.

        Returns:
            tuple[Any, Any, str]: A tuple containing the transformed training
            and testing data arrays, the path to the saved preprocessing object.
        """
        try:
            logger.info("Fetching train and test data")
            train_df = pd.read_csv(self.filepath_config.train_data_path)
            test_df = pd.read_csv(self.filepath_config.test_data_path)

            logger.info("Read train and test data completed")
            logger.info(f"Train data shape: {train_df.shape}, Test data shape: {test_df.shape}")

            # Handle problematic characters in the dataset
            logger.info("Preprocessing data to handle special characters")
            
            # Function to clean problematic characters from passwords
            def clean_password(password):
                try:
                    if not isinstance(password, str):
                        return str(password)
                        
                    # Identify problematic characters like superscripts (³) and other special characters
                    # that cause issues during processing
                    clean_pwd = ""
                    for char in password:
                        category = unicodedata.category(char)
                        
                        # Skip superscripts, subscripts, and other problematic characters
                        if category in ('No', 'So') and ord(char) > 128:  # Other Number, Other Symbol categories with non-ASCII
                            continue
                            
                        clean_pwd += char
                    
                    return clean_pwd
                except Exception as e:
                    logger.warning(f"Error cleaning password: {str(e)}")
                    return str(password)  # Return original as string
            
            # Apply password cleaning to both dataframes
            train_df['password'] = train_df['password'].apply(clean_password)
            test_df['password'] = test_df['password'].apply(clean_password)
            
            # Only keep rows where password can be properly processed
            valid_train_rows = []
            for idx, row in train_df.iterrows():
                try:
                    # Basic validation to filter out problematic entries
                    password = str(row['password'])
                    if password and len(password) >= 4 and len(password) <= 64:
                        # Check for superscript/subscript digits which could cause int() conversion issues
                        if not any(c for c in password if unicodedata.category(c) == 'No'):
                            valid_train_rows.append(idx)
                except Exception as e:
                    logger.warning(f"Skipping problematic train row {idx}: {str(e)}")
            
            valid_test_rows = []
            for idx, row in test_df.iterrows():
                try:
                    # Basic validation to filter out problematic entries
                    password = str(row['password'])
                    if password and len(password) >= 4 and len(password) <= 64:
                        # Check for superscript/subscript digits which could cause int() conversion issues
                        if not any(c for c in password if unicodedata.category(c) == 'No'):
                            valid_test_rows.append(idx)
                except Exception as e:
                    logger.warning(f"Skipping problematic test row {idx}: {str(e)}")
            
            train_df = train_df.loc[valid_train_rows]
            test_df = test_df.loc[valid_test_rows]
            
            logger.info(f"After filtering: Train data shape: {train_df.shape}, Test data shape: {test_df.shape}")

            logger.info("Splitting data")

            X_train = train_df.drop(columns=[target], axis=1)
            y_train = train_df[target]

            X_test = test_df.drop(columns=[target], axis=1)
            y_test = test_df[target]

            logger.info(
                "Applying preprocessing object on training dataframe and testing dataframe."
            )

            # Apply transformations with error handling
            try:
                X_train_arr = transformer.fit_transform(X_train)
                X_test_arr = transformer.transform(X_test)
            except Exception as e:
                logger.error(f"Error during transformation: {str(e)}")
                raise CustomException(f"Transformation error: {str(e)}", sys)

            train_arr = np.c_[X_train_arr, np.array(y_train)]
            test_arr = np.c_[X_test_arr, np.array(y_test)]

            logger.info("Saved preprocessing object.")

            save_object(
                file_path=self.filepath_config.preprocessor_path,
                obj=transformer,
            )

            return (
                train_arr,
                test_arr,
                self.filepath_config.preprocessor_path,
            )
        except Exception as error:
            raise CustomException(error, sys) from error


if __name__ == "__main__":
    data_transformation = DataTransformation()
    transformer_obj = data_transformation.get_data_transformer_object(
        features=["password"]
    )
    data_transformation.initiate_data_transformation(
        target="strength", transformer=transformer_obj
    )
