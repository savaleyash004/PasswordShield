# """
# A module for training and evaluating different machine learning models
# for password strength prediction.
# """

# import sys
# from typing import Any, Dict, Tuple

# import numpy as np
# from sklearn.ensemble import (
#     AdaBoostRegressor,
#     RandomForestRegressor,
# )
# from sklearn.linear_model import LinearRegression
# from sklearn.metrics import (
#     mean_absolute_error,
#     mean_squared_error,
#     r2_score,
# )
# from sklearn.neighbors import KNeighborsRegressor
# from sklearn.tree import DecisionTreeRegressor

# try:
#     import xgboost as xgb
#     XGBOOST_AVAILABLE = True
# except ImportError:
#     XGBOOST_AVAILABLE = False

# try:
#     import lightgbm as lgb
#     LIGHTGBM_AVAILABLE = True
# except ImportError:
#     LIGHTGBM_AVAILABLE = False

# try:
#     from catboost import CatBoostRegressor
#     CATBOOST_AVAILABLE = True
# except ImportError:
#     CATBOOST_AVAILABLE = False

# from src.interface.config import FilePathConfig
# from src.middleware.exception import CustomException
# from src.middleware.logger import logger
# from src.utils.file_manager import save_object


# class ModelTrainer:
#     """
#     A class for training and evaluating machine learning models.
#     """

#     def __init__(self) -> None:
#         """
#         Initialize the ModelTrainer object.
#         """

#         self.filepath_config = FilePathConfig()

#     def evaluate_models(
#         self, train_array: np.ndarray[Any, Any], test_array: np.ndarray[Any, Any]
#     ) -> Dict[str, float]:
#         """
#         Evaluate various regression models on the provided train and test data.

#         Args:
#             train_array (np.ndarray): Array containing training features and target.
#             test_array (np.ndarray): Array containing testing features and target.

#         Raises:
#             CustomException: If there's an error during model training or evaluation.

#         Returns:
#             Dict[str, float]: Dictionary containing model names and their corresponding
#                           R-squared scores.
#         """
#         try:
#             logger.info("Split training and test input data")
#             X_train, y_train, X_test, y_test = (
#                 train_array[:, :-1],
#                 train_array[:, -1],
#                 test_array[:, :-1],
#                 test_array[:, -1],
#             )

#             # Define optimization parameters for faster training
#             fast_mode = True  # Set to True for faster training, False for more thorough evaluation
            
#             # Models with hyperparameters optimized for speed vs accuracy
#             models = {
#                 "Linear Regression": LinearRegression(),
#                 "Decision Tree": DecisionTreeRegressor(
#                     max_depth=6 if fast_mode else 10,
#                     min_samples_split=10 if fast_mode else 2,
#                 ),
#                 "Random Forest": RandomForestRegressor(
#                     n_estimators=100 if fast_mode else 200,
#                     max_depth=10 if fast_mode else 20,
#                     n_jobs=-1,
#                     verbose=0,
#                 ),
#                 "AdaBoost Regressor": AdaBoostRegressor(
#                     n_estimators=50 if fast_mode else 100,
#                 ),
#                 "K-Neighbors Regressor": KNeighborsRegressor(
#                     n_neighbors=5 if fast_mode else 7
#                 ),
#             }
            
#             # Add gradient boosting models if available
#             if XGBOOST_AVAILABLE:
#                 models["XGBoost"] = xgb.XGBRegressor(
#                     n_estimators=100 if fast_mode else 200,
#                     max_depth=6 if fast_mode else 10,
#                     learning_rate=0.1,
#                     n_jobs=-1,
#                     verbosity=0,
#                 )
                
#             if LIGHTGBM_AVAILABLE:
#                 models["LightGBM"] = lgb.LGBMRegressor(
#                     n_estimators=100 if fast_mode else 200,
#                     max_depth=6 if fast_mode else 10,
#                     learning_rate=0.1,
#                     n_jobs=-1,
#                     verbose=-1,
#                 )
                
#             if CATBOOST_AVAILABLE:
#                 models["CatBoost"] = CatBoostRegressor(
#                     iterations=100 if fast_mode else 200,
#                     depth=6 if fast_mode else 10,
#                     learning_rate=0.1,
#                     verbose=0,
#                 )

#             model_report: Dict[str, float] = {}
#             logger.info("Evaluate models")

#             for model_name, model in models.items():
#                 logger.info("Training %s", model_name)
                
#                 # Special handling for gradient boosting models with early stopping
#                 if model_name in ["XGBoost", "LightGBM", "CatBoost"] and not fast_mode:
#                     # Create a validation set for early stopping
#                     val_size = int(X_train.shape[0] * 0.2)
#                     X_val = X_train[-val_size:]
#                     y_val = y_train[-val_size:]
#                     X_train_subset = X_train[:-val_size]
#                     y_train_subset = y_train[:-val_size]
                    
#                     if model_name == "XGBoost" and XGBOOST_AVAILABLE:
#                         model.fit(
#                             X_train_subset, y_train_subset,
#                             eval_set=[(X_val, y_val)],
#                             early_stopping_rounds=10,
#                             verbose=False
#                         )
#                     elif model_name == "LightGBM" and LIGHTGBM_AVAILABLE:
#                         model.fit(
#                             X_train_subset, y_train_subset,
#                             eval_set=[(X_val, y_val)],
#                             early_stopping_rounds=10,
#                             verbose=-1
#                         )
#                     elif model_name == "CatBoost" and CATBOOST_AVAILABLE:
#                         model.fit(
#                             X_train_subset, y_train_subset,
#                             eval_set=[(X_val, y_val)],
#                             early_stopping_rounds=10,
#                             verbose=False
#                         )
#                 else:
#                     # Regular training for other models
#                     model.fit(X_train, y_train)

#                 y_test_pred = model.predict(X_test)
#                 test_model_score = r2_score(y_test, y_test_pred)
#                 model_report[model_name] = test_model_score
#                 logger.info("%s: %f", model_name, test_model_score)

#             return model_report

#         except Exception as error:
#             raise CustomException(error, sys) from error

#     def select_best_model(
#         self, report: Dict[str, float], test_array: np.ndarray[Any, Any]
#     ) -> Tuple[str, float]:
#         """
#         Select the best model based on the evaluation report and save it.

#         Args:
#             report (Dict[str, float]): Dictionary containing model names and their
#                                  corresponding R-squared scores.
#             test_array (np.ndarray): Array containing testing features and target.

#         Returns:
#             Tuple[str, float]: A tuple containing the name of the best model and its R-squared score.
#         """
#         model_names = list(report.keys())
#         scores = list(report.values())

#         if not model_names:
#             raise CustomException(
#                 "No models available. Cannot select the best model.", sys
#             )

#         best_model_name = model_names[0]
#         best_model_score = scores[0]

#         for name, score in report.items():
#             if score > best_model_score:
#                 best_model_name = name
#                 best_model_score = score

#         logger.info("Best model: %s Score: %f", best_model_name, best_model_score)

#         logger.info("Retrain best model on entire dataset")
#         X, y = test_array[:, :-1], test_array[:, -1]

#         if best_model_name == "Linear Regression":
#             best_model = LinearRegression()
#         elif best_model_name == "Decision Tree":
#             best_model = DecisionTreeRegressor()
#         elif best_model_name == "Random Forest":
#             best_model = RandomForestRegressor(n_jobs=-1)
#         elif best_model_name == "AdaBoost Regressor":
#             best_model = AdaBoostRegressor()
#         elif best_model_name == "K-Neighbors Regressor":
#             best_model = KNeighborsRegressor()
#         elif best_model_name == "XGBoost" and XGBOOST_AVAILABLE:
#             best_model = xgb.XGBRegressor(n_jobs=-1, verbosity=0)
#         elif best_model_name == "LightGBM" and LIGHTGBM_AVAILABLE:
#             best_model = lgb.LGBMRegressor(n_jobs=-1, verbose=-1)
#         elif best_model_name == "CatBoost" and CATBOOST_AVAILABLE:
#             best_model = CatBoostRegressor(verbose=0)
#         else:
#             raise CustomException(
#                 f"Model {best_model_name} is not defined.", sys
#             )

#         best_model.fit(X, y)

#         logger.info("Saved model")
#         save_object(file_path=self.filepath_config.model_path, obj=best_model)

#         return best_model_name, best_model_score


# if __name__ == "__main__":
#     from src.components.data_transformation import DataTransformation

#     data_transformation = DataTransformation()
#     transformer_obj = data_transformation.get_data_transformer_object(
#         features=["password"]
#     )
#     train_arr, test_arr, _ = data_transformation.initiate_data_transformation(
#         target="strength", transformer=transformer_obj
#     )
#     model_trainer = ModelTrainer()
#     report = model_trainer.evaluate_models(train_arr, test_arr)
#     name_model, score = model_trainer.select_best_model(report, test_arr)
#     logger.info("Best model: %s Score: %s", name_model, score)
"""
A module for training and evaluating different machine learning models
for password strength prediction.
"""

import sys
from typing import Any, Dict, Tuple

import numpy as np
from sklearn.ensemble import AdaBoostRegressor, RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.neighbors import KNeighborsRegressor
from sklearn.tree import DecisionTreeRegressor

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

try:
    from catboost import CatBoostRegressor
    CATBOOST_AVAILABLE = True
except ImportError:
    CATBOOST_AVAILABLE = False

from src.interface.config import FilePathConfig
from src.middleware.exception import CustomException
from src.middleware.logger import logger
from src.utils.file_manager import save_object


class ModelTrainer:
    """
    A class for training and evaluating machine learning models.
    """

    def __init__(self) -> None:
        self.filepath_config = FilePathConfig()

    def evaluate_models(
        self, train_array: np.ndarray[Any, Any], test_array: np.ndarray[Any, Any]
    ) -> Dict[str, Dict[str, float]]:
        """
        Evaluate various regression models on the provided train and test data.

        Returns a dictionary with model name as keys and metric dictionary as values.
        """
        try:
            logger.info("Splitting training and test data")
            X_train, y_train = train_array[:, :-1], train_array[:, -1]
            X_test, y_test = test_array[:, :-1], test_array[:, -1]

            fast_mode = True  # Toggle for fast vs thorough training

            models = {
                "Linear Regression": LinearRegression(),
                "Decision Tree": DecisionTreeRegressor(
                    max_depth=6 if fast_mode else 10,
                    min_samples_split=10 if fast_mode else 2,
                ),
                "Random Forest": RandomForestRegressor(
                    n_estimators=100 if fast_mode else 200,
                    max_depth=10 if fast_mode else 20,
                    n_jobs=-1,
                ),
                "AdaBoost Regressor": AdaBoostRegressor(
                    n_estimators=50 if fast_mode else 100,
                ),
                "K-Neighbors Regressor": KNeighborsRegressor(
                    n_neighbors=5 if fast_mode else 7
                ),
            }

            if XGBOOST_AVAILABLE:
                models["XGBoost"] = xgb.XGBRegressor(
                    n_estimators=100 if fast_mode else 200,
                    max_depth=6 if fast_mode else 10,
                    learning_rate=0.1,
                    n_jobs=-1,
                    verbosity=0,
                )
            if LIGHTGBM_AVAILABLE:
                models["LightGBM"] = lgb.LGBMRegressor(
                    n_estimators=100 if fast_mode else 200,
                    max_depth=6 if fast_mode else 10,
                    learning_rate=0.1,
                    n_jobs=-1,
                    verbose=-1,
                )
            if CATBOOST_AVAILABLE:
                models["CatBoost"] = CatBoostRegressor(
                    iterations=100 if fast_mode else 200,
                    depth=6 if fast_mode else 10,
                    learning_rate=0.1,
                    verbose=0,
                )

            model_report: Dict[str, Dict[str, float]] = {}
            logger.info("Evaluating models...")

            for name, model in models.items():
                logger.info("Training model: %s", name)
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)

                model_report[name] = {
                    "r2": r2_score(y_test, y_pred),
                    "mae": mean_absolute_error(y_test, y_pred),
                    "rmse": mean_squared_error(y_test, y_pred, squared=False),
                }

                logger.info("%s => R2: %.4f, MAE: %.4f, RMSE: %.4f",
                            name, model_report[name]["r2"],
                            model_report[name]["mae"],
                            model_report[name]["rmse"])

            return model_report

        except Exception as error:
            raise CustomException(error, sys) from error

    def select_best_model(
        self, report: Dict[str, Dict[str, float]], train_array: np.ndarray, test_array: np.ndarray
    ) -> Tuple[str, float]:
        """
        Selects and saves the best model based on R² score.
        Trains it on the combined train + test set before saving.
        """
        if not report:
            raise CustomException("No models were evaluated.", sys)

        best_model_name = max(report, key=lambda x: report[x]["r2"])
        best_model_score = report[best_model_name]["r2"]
        logger.info("Best model selected: %s (R² = %.4f)", best_model_name, best_model_score)

        full_data = np.concatenate([train_array, test_array], axis=0)
        X, y = full_data[:, :-1], full_data[:, -1]

        model_map = {
            "Linear Regression": LinearRegression(),
            "Decision Tree": DecisionTreeRegressor(),
            "Random Forest": RandomForestRegressor(n_jobs=-1),
            "AdaBoost Regressor": AdaBoostRegressor(),
            "K-Neighbors Regressor": KNeighborsRegressor(),
            "XGBoost": xgb.XGBRegressor(n_jobs=-1, verbosity=0) if XGBOOST_AVAILABLE else None,
            "LightGBM": lgb.LGBMRegressor(n_jobs=-1, verbose=-1) if LIGHTGBM_AVAILABLE else None,
            "CatBoost": CatBoostRegressor(verbose=0) if CATBOOST_AVAILABLE else None,
        }

        best_model = model_map.get(best_model_name)
        if best_model is None:
            raise CustomException(f"Model {best_model_name} is not supported or available.", sys)

        logger.info("Retraining best model on full dataset")
        best_model.fit(X, y)
        save_object(file_path=self.filepath_config.model_path, obj=best_model)
        logger.info("Best model saved successfully at %s", self.filepath_config.model_path)

        return best_model_name, best_model_score


if __name__ == "__main__":
    from src.components.data_transformation import DataTransformation

    data_transformation = DataTransformation()
    transformer = data_transformation.get_data_transformer_object(features=["password"])
    train_arr, test_arr, _ = data_transformation.initiate_data_transformation(
        target="strength", transformer=transformer
    )

    model_trainer = ModelTrainer()
    evaluation_report = model_trainer.evaluate_models(train_arr, test_arr)
    best_model_name, best_score = model_trainer.select_best_model(evaluation_report, train_arr, test_arr)
    logger.info("Final best model: %s with R² score: %.4f", best_model_name, best_score)
