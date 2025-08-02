"""This module defines a FastAPI router for predicting password strength based
on a given password."""

from fastapi import APIRouter

from src.api.components import generate_strong_password, password_strength_component
from src.api.schema import (
    GenerateRequest,
    GenerateResponse,
    PredictionRequest,
    PredictionResponse,
    VulnerabilityAssessment,
)
from src.api.utils import assess_password_vulnerability, calc_entropy, calc_strength
from src.middleware.logger import logger

router = APIRouter()


@router.post(
    "/predict",
    summary="Predict password strength",
    description="Predict the strength of a given password.",
    tags=["API"],
    response_model=PredictionResponse,
)  # type: ignore
async def password_strength(
    request: PredictionRequest,
) -> PredictionResponse:
    """
    Predict the strength of a given password.

    Args:
        request (PredictionRequest): The request containing the password.

    Returns:
        PredictionResponse: The response containing the password and
        its strength prediction and other parameters.
    """
    return password_strength_component(request)


@router.post(
    "/generate",
    summary="Generate password",
    description="Generate strong password of a given length.",
    tags=["API"],
    response_model=GenerateResponse,
)  # type: ignore
async def generate_password(
    request: GenerateRequest,
) -> GenerateResponse:
    """
    Generate strong password of a given length.

    Args:
        request (GenerateRequest): The request containing the length.

    Returns:
        GenerateResponse: The response containing the password and
        its strength prediction and other parameters.
    """
    return generate_strong_password(request)


@router.post(
    "/vulnerability",
    summary="Assess password vulnerability",
    description="Assess the vulnerability of a password against different attack types.",
    tags=["API"],
    response_model=VulnerabilityAssessment,
)  # type: ignore
async def assess_vulnerability(
    request: PredictionRequest,
) -> VulnerabilityAssessment:
    """
    Assess the vulnerability of a password against different attack types.

    Args:
        request (PredictionRequest): The request containing the password.

    Returns:
        VulnerabilityAssessment: The vulnerability assessment for different attack types.
    """
    logger.info("Called vulnerability assessment function")
    
    password = request.password
    strength = calc_strength(password)
    entropy = calc_entropy(password)
    
    # Get vulnerability assessment
    vulnerability = assess_password_vulnerability(password, strength, entropy)
    
    # Log the assessment
    logger.info(f"Vulnerability assessment completed for {password}")
    for attack_type, details in vulnerability.items():
        logger.info(f"  {attack_type}: {details.get('risk')}")
    
    return vulnerability
