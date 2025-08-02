"""Module summary: This module contains pytest test cases for the FastAPI
application, including tests for the root endpoint and password strength
prediction endpoint."""

import pytest
from fastapi.testclient import TestClient

from src.api.app import app

client = TestClient(app)


def test_read_root() -> None:
    """Test case for the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Server running successfully"}


def test_predict_password_strength_valid(valid_password: str) -> None:
    """Test case for predicting password strength with a valid password.

    Args:
        valid_password (str): The valid password.
    """
    response = client.post("/predict", json={"password": valid_password})
    assert response.status_code == 200
    assert response.json()["class_strength"] == "Very strong"


def test_predict_password_strength_invalid_short(
    invalid_short_password: str,
) -> None:
    """Test case for predicting password strength with an invalid short
    password.

    Args:
        invalid_short_password (str): The invalid short password.
    """
    response = client.post(
        "/predict", json={"password": invalid_short_password}
    )
    assert response.status_code == 400
    assert "Invalid too short password" in response.json()["detail"]


def test_predict_password_strength_invalid_characters(
    invalid_characters_password: str,
) -> None:
    """Test case for predicting password strength with an invalid password
    containing unsupported characters.

    Args:
        invalid_characters_password (str): The invalid password with unsupported
        characters.
    """
    response = client.post(
        "/predict", json={"password": invalid_characters_password}
    )
    assert response.status_code == 400
    assert "Invalid password characters" in response.json()["detail"]


def test_predict_password_strength_invalid_long(
    invalid_long_password: str,
) -> None:
    """Test case for predicting password strength with an invalid long password.

    Args:
        invalid_long_password (str): The invalid long password.
    """
    response = client.post(
        "/predict", json={"password": invalid_long_password}
    )
    assert response.status_code == 400
    assert "Invalid password length" in response.json()["detail"]


def test_predict_password_strength_empty() -> None:
    """Test case for predicting password strength with an empty password."""
    response = client.post("/predict", json={"password": None})
    assert response.status_code == 422
    assert (
        "type_error.none.not_allowed" in response.json()["detail"][0]["type"]
    )


if __name__ == "__main__":
    pytest.main()
