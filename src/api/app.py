"""This module defines a FastAPI application with a root endpoint
and includes a router for password strength prediction."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers import router
from src.middleware.exception import CustomException
from src.middleware.logger import logger

APP_DESC = """
The PassShield API is a powerful tool designed to enhance password security and empower users with the ability to assess password strength and generate secure passwords. Whether you're a developer integrating password strength prediction into your application or an end user looking for a reliable password generation service, the PassShield API has you covered.

## Features

- **Password Strength Prediction:** Get an accurate assessment of the strength of a password, helping you make informed decisions about your password choices.

- **Secure Password Generation:** Generate strong and secure passwords based on customizable criteria, ensuring you have robust passwords that meet your needs. Supports multiple writing systems including Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari (for Hindi and Marathi), Bengali, Tamil, Telugu, Kannada, Malayalam, Thai, Japanese, Chinese, Korean, and many other world languages.

- **Multilingual Script Detection:** Automatically identifies which writing systems are used in a password, providing insights into its diversity and complexity.

- **API Integration:** Seamlessly integrate the PassShield API into your applications, providing your users with an additional layer of security and peace of mind.

## How It Works

The PassShield API utilizes state-of-the-art machine learning techniques to predict password strength based on a variety of features and characteristics. It combines data analysis, feature engineering, and model selection to provide reliable and accurate predictions.

## Getting Started

To get started with the PassShield API, follow the instructions provided in the project's [GitHub repository](https://github.com/Sahil252004/PassShield). You can set up the API locally or access it remotely.

## API Documentation

Explore the comprehensive API documentation and interactive Swagger interface to understand the available endpoints, request and response structures, and usage examples. You can access the API documentation at [http://localhost:8000/docs](http://localhost:8000/docs) after starting the local server.

## Docker Image

For easy deployment and scalability, a Docker image of the PassShield API is available on Docker Hub. By pulling and running the image, you can quickly set up the API in a containerized environment.

## Contribution and Contact

Contributions to the PassShield API are welcome! Whether you're interested in fixing a bug, enhancing existing features, or adding new functionality, your contributions are valuable. Feel free to reach out to the project author, [Sahil](mailto:karthikajitudy@gmail.com), for any questions or feedback.

## License

The PassShield API is distributed under the [Sahil](https://github.com/Sahil252004/PassShield/blob/main/LICENSE). This license allows you to use, modify, and distribute the software, subject to the terms and conditions outlined in the license.
"""

app = FastAPI(
    title="PassShield API",
    description=APP_DESC,
    summary="Predict and Generate Password Strength",
    version="1.1.0",
    contact={
        "name": "Sahil",
        "url": "https://github.com/Sahil252004",
        "email": "karthikajitudy@gmail.com",
    },
    license_info={
        "name": "Sahil",
        "url": "https://github.com/Sahil252004/PassShield/blob/main/LICENSE",
    },
)

# Configure CORS to allow requests from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Add custom exception handler
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException):
    """Handle CustomException and return a proper JSON response"""
    logger.error(f"CustomException: {exc}")
    return JSONResponse(
        status_code=500,
        content=exc.to_dict(),
    )

# Include the router with explicit prefix
app.include_router(router, prefix="")

# Log available endpoints
logger.info("API initialized with the following endpoints:")
logger.info("- GET /")
logger.info("- POST /predict (Password strength analysis)")
logger.info("- POST /generate (Password generation)")
logger.info("- POST /vulnerability (Password vulnerability assessment)")


@app.get(
    "/", summary="Root endpoint", description="Returns a success message."
)  # type: ignore
def read_root() -> dict[str, str]:
    """
    Get the root endpoint.

    Returns:
        dict: A dictionary containing a success message.
    """
    logger.info("Server running successfully")
    endpoints = {
        "message": "Server running successfully",
        "available_endpoints": [
            {"path": "/", "method": "GET", "description": "Root endpoint"},
            {"path": "/predict", "method": "POST", "description": "Password strength analysis"},
            {"path": "/generate", "method": "POST", "description": "Password generation"},
            {"path": "/vulnerability", "method": "POST", "description": "Password vulnerability assessment"},
            {"path": "/docs", "method": "GET", "description": "API documentation"},
        ]
    }
    return endpoints
