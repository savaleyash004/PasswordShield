"""
This module contains test cases for the ModelTrainer class.
"""
import pytest
from sklearn.tree import DecisionTreeRegressor

from src.components.data_transformation import DataTransformation
from src.components.model_trainer import ModelTrainer


def test_init(model_trainer: ModelTrainer) -> None:
    """Test case for the `__init__` method.

    Args:
        model_trainer (ModelTrainer): The ModelTrainer instance.
    """
    assert isinstance(model_trainer.models, dict)
    assert len(model_trainer.models) == 1
    assert "Decision Tree" in model_trainer.models
    assert isinstance(
        model_trainer.models["Decision Tree"], DecisionTreeRegressor
    )
    assert isinstance(model_trainer.params, dict)
    assert len(model_trainer.params) == 1
    assert "Decision Tree" in model_trainer.params
    assert isinstance(model_trainer.params["Decision Tree"], dict)


def test_evaluate_models(
    model_trainer: ModelTrainer, data_transformation: DataTransformation
) -> None:
    """Test case for the `evaluate_models` method.

    Args:
        model_trainer (ModelTrainer): The ModelTrainer instance.
        data_transformation (DataTransformation): The DataTransformation instance.
    """
    transformer_obj = data_transformation.get_data_transformer_object(
        features=["password"]
    )
    (
        train_array,
        test_array,
        _,
    ) = data_transformation.initiate_data_transformation(
        target="strength", transformer=transformer_obj
    )
    result = model_trainer.evaluate_models(train_array, test_array)
    assert isinstance(result, dict)
    assert len(result) == 1
    assert list(result.keys()) == ["Decision Tree"]
    assert isinstance(result["Decision Tree"], float)


def test_select_best_model(
    model_trainer: ModelTrainer, data_transformation: DataTransformation
) -> None:
    """Test case for the `select_best_model` method.

    Args:
        model_trainer (ModelTrainer): The ModelTrainer instance.
        data_transformation (DataTransformation): The DataTransformation instance.
    """
    transformer_obj = data_transformation.get_data_transformer_object(
        features=["password"]
    )
    (
        train_array,
        test_array,
        _,
    ) = data_transformation.initiate_data_transformation(
        target="strength", transformer=transformer_obj
    )
    test_report = model_trainer.evaluate_models(train_array, test_array)
    result = model_trainer.select_best_model(test_report, test_array)
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], str)
    assert isinstance(result[1], float)


if __name__ == "__main__":
    pytest.main()
