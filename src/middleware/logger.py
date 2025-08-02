"""
Custom logger configuration for logging to both a file and the console.
"""
import logging
import os
from datetime import datetime

import colorlog

LOG_FILE = f"{datetime.now().strftime('%d_%m_%Y')}.log"
logs_folder = os.path.join(os.getcwd(), "logs")
os.makedirs(logs_folder, exist_ok=True)

LOG_FILE_PATH = os.path.join(logs_folder, LOG_FILE)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create a file handler
file_handler = logging.FileHandler(LOG_FILE_PATH)
file_handler.setLevel(logging.INFO)

# Create a stream handler
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)

# Create color formatter for console log messages
console_formatter = colorlog.ColoredFormatter(
    "[ %(asctime)s ] %(lineno)d %(name)s - "
    "%(log_color)s%(levelname)s%(reset)s - %(message)s",
    log_colors={
        "DEBUG": "white",
        "INFO": "blue",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold_red",
    },
)

# Create formatter for file log messages
file_formatter = logging.Formatter(
    "[ %(asctime)s ] %(lineno)d %(name)s - %(levelname)s - %(message)s"
)

# Set formatters for handlers
file_handler.setFormatter(file_formatter)
stream_handler.setFormatter(console_formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

if __name__ == "__main__":
    # Log messages at different levels
    logger.debug("This is a debug message")
    logger.info("This is an informational message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
