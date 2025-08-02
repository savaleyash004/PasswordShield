"""
Custom exception class and helper functions for exception
handling and logging.
"""
import sys
from typing import Any, Dict

from src.middleware.logger import logger


class CustomException(Exception):
    """Custom exception class for handling specific exceptions."""

    def __init__(self, error_message: Any, error_detail: Any):
        self.error_message = error_message_detail(
            error_message, error_detail=error_detail
        )

    def __str__(self) -> str:
        return self.error_message
        
    def __repr__(self) -> str:
        return self.__str__()
        
    def to_dict(self) -> Dict[str, str]:
        """Convert exception to dictionary for JSON serialization."""
        return {"error": self.error_message}


def error_message_detail(error: Any, error_detail: Any) -> str:
    """Format and log error details,
    and return the error messages a string."""
    _, _, exc_tb = error_detail.exc_info()
    if exc_tb is None:
        raise CustomException(error, sys) from error
    file_name = exc_tb.tb_frame.f_code.co_filename
    logger.error(
        "Error occurred in python script name [%s] "
        "line number [%d] error message [%s]",
        file_name,
        exc_tb.tb_lineno,
        str(error),
    )
    return str(error)


if __name__ == "__main__":
    try:
        _ = 1 / 0
    except Exception as e:
        logger.debug("Test CustomException")
        raise CustomException(e, sys) from e
