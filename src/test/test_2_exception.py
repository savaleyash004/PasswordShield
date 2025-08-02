"""
Unit tests for the CustomException and error_message_detail functions.
"""
import sys

import pytest

from src.middleware.exception import CustomException, error_message_detail
from src.middleware.logger import logger


def test_custom_exception() -> None:
    """
    Test CustomException by raising a ZeroDivisionError and wrapping it in a
    CustomException.
    """
    with pytest.raises(CustomException):
        try:
            _ = 10 / 0
        except ZeroDivisionError as err:
            logger.debug("Test CustomException")
            raise CustomException(err, sys) from err


def test_error_message_detail() -> None:
    """
    Test error_message_detail function by raising a ZeroDivisionError and
    passing it to the function.
    """
    error = ZeroDivisionError("division by zero")
    try:
        raise error
    except ZeroDivisionError as err:
        message = error_message_detail(err, sys)
        assert isinstance(message, str)


if __name__ == "__main__":
    pytest.main()
