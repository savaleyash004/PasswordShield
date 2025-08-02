"""Generates kaggle.json file"""
import json

from src.interface.config import config

# Generate kaggle.json
kaggle_credentials = {
    "username": config["KAGGLE_USERNAME"],
    "key": config["KAGGLE_KEY"],
}

# Save the credentials as kaggle.json
with open("kaggle.json", "w", encoding="utf-8") as file:
    json.dump(kaggle_credentials, file)
