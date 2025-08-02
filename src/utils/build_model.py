"""Build Model"""
import argparse
import json
import os
from dotenv import load_dotenv

from src.interface.config import config
from src.pipe.pipeline import Pipeline

# Load environment variables directly from .env file
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
print(f"Loading .env file from: {env_path}")
load_dotenv(env_path)

# Get credentials from environment
kaggle_username = os.getenv('KAGGLE_USERNAME')
kaggle_key = os.getenv('KAGGLE_KEY')

if not kaggle_username or not kaggle_key:
    raise ValueError("Kaggle credentials not found in .env file. Please ensure KAGGLE_USERNAME and KAGGLE_KEY are set.")

# Generate kaggle.json
kaggle_credentials = {
    "username": kaggle_username,
    "key": kaggle_key,
}


# Save the credentials as kaggle.json
def generate_json(values: dict[str, str]) -> None:
    """Generate a JSON file with the provided values.

    Args:
        values (dict[str, str]): The dictionary containing key-value pairs
        to be written to the JSON file.
    """
    with open("kaggle.json", "w", encoding="utf-8") as file:
        json.dump(values, file)


def process_and_train() -> None:
    """This function utilizes the Pipeline class to perform data pushing and training."""
    pipeline = Pipeline()
    pipeline.push_data()
    pipeline.train()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process and train the model")
    parser.add_argument(
        "--train",
        action="store_true",
        help="Whether to process and train the model",
    )
    args = parser.parse_args()

    generate_json(kaggle_credentials)

    if args.train:
        process_and_train()
