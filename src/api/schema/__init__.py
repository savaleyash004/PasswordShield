"""This module defines classes for password strength prediction and generation
requests and responses using Pydantic models."""
from pydantic import BaseModel, Field
from typing import Dict, List, Optional


class PredictionRequest(BaseModel):  # type: ignore
    """A request model for password strength prediction.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """

    password: str = Field(
        ..., description="The password to predict its strength"
    )


class RiskAssessment(BaseModel):  # type: ignore
    """A model for individual risk assessment.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """
    
    risk: str = Field(..., description="Risk level (Very Low, Low, Moderate, High, Very High)")
    description: str = Field(..., description="Description of the risk level")


class VulnerabilityAssessment(BaseModel):  # type: ignore
    """A model for password vulnerability assessment against different attack types.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """

    dictionary_attack: RiskAssessment = Field(
        ..., description="Vulnerability to dictionary attacks which use common words and phrases"
    )
    brute_force_attack: RiskAssessment = Field(
        ..., description="Vulnerability to brute force attacks which try all possible combinations"
    )
    hybrid_attack: RiskAssessment = Field(
        ..., description="Vulnerability to hybrid attacks which combine dictionary and brute force methods"
    )
    rainbow_table_attack: RiskAssessment = Field(
        ..., description="Vulnerability to rainbow table attacks which use precomputed hash tables"
    )
    table_attack: RiskAssessment = Field(
        ..., description="Vulnerability to look-up table attacks which search through databases of known passwords"
    )


class BreachInfo(BaseModel):  # type: ignore
    """A model for password breach information.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """

    is_breached: bool = Field(
        False, description="Whether the password was found in any breach"
    )
    breach_count: int = Field(
        0, description="Total number of times the password appeared in breaches"
    )
    in_known_breach: bool = Field(
        False, description="Whether the password appears in known breaches"
    )
    in_rockyou: bool = Field(
        False, description="Whether the password appears in the RockYou dataset"
    )
    rockyou_count: int = Field(
        0, description="Number of times the password appeared in the RockYou dataset"
    )
    breach_source: List[str] = Field(
        [], description="List of sources where the password was found"
    )


class HashTimeInfo(BaseModel):  # type: ignore
    """Information about crack time for a specific hash algorithm.
    
    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """
    
    seconds: float = Field(..., description="Crack time in seconds")
    display: str = Field(..., description="Human-readable crack time")


class PredictionResponse(BaseModel):  # type: ignore
    """A response model for password strength prediction.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """

    password: str = Field(..., description="The input password")
    length: int = Field(..., description="The length of password")
    strength: float = Field(
        ..., description="The strength prediction of the password"
    )
    class_strength: str = Field(
        ..., description="The class strength prediction of the password: 'Weak', 'Moderate', 'Strong', or 'Very strong'"
    )
    entropy: float = Field(
        ..., description="The measurement of how unpredictable is the password"
    )
    crack_time_sec: float = Field(
        ..., description="The time taken to crack the password in sec"
    )
    crack_time: str = Field(
        ..., description="The time taken to crack the password"
    )
    has_pattern: bool = Field(
        ..., description="Whether the password contains common patterns like dates"
    )
    password_tips: list[str] = Field(
        ..., description="Tips to improve the password security"
    )
    security_score: str = Field(
        ..., description="A letter grade (A-F) representing password security"
    )
    has_non_latin: bool = Field(
        False, description="Whether the password contains non-Latin characters"
    )
    scripts_used: list[str] = Field(
        [], description="The writing systems/scripts detected in the password (Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari, Bengali, Tamil, Telugu, Kannada, Malayalam, Thai, Japanese, Chinese, Korean, etc.)"
    )
    vulnerability_assessment: VulnerabilityAssessment = Field(
        ..., description="Assessment of the password's vulnerability to different attack types"
    )
    breach_info: BreachInfo = Field(
        default_factory=BreachInfo, description="Information about the password's presence in known data breaches"
    )
    hash_crack_times: Dict[str, HashTimeInfo] = Field(
        default_factory=dict, description="Crack time estimates for different hash algorithms using hashcat benchmark data"
    )


class GenerateRequest(BaseModel):  # type: ignore
    """A request model for password generation.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """

    length: int = Field(..., description="The length of password")
    include_non_latin: bool = Field(
        False, description="Whether to include non-Latin characters from various world languages (including Cyrillic, Greek, Arabic, Hebrew, Devanagari, Bengali, Tamil, Telugu, Kannada, Malayalam, Thai, Japanese, Chinese, Korean, and many others)"
    )


class GenerateResponse(BaseModel):  # type: ignore
    """A response model for password generation.

    Args:
        BaseModel (type): The Pydantic BaseModel class.
    """

    password: str = Field(..., description="The generated password")
    length: int = Field(..., description="The length of password")
    strength: float = Field(
        ..., description="The strength prediction of the password"
    )
    class_strength: str = Field(
        ..., description="The class strength prediction of the password: 'Weak', 'Moderate', 'Strong', or 'Very strong'"
    )
    entropy: float = Field(
        ..., description="The measurement of how unpredictable is the password"
    )
    crack_time_sec: float = Field(
        ..., description="The time taken to crack the password in sec"
    )
    crack_time: str = Field(
        ..., description="The time taken to crack the password"
    )
    has_pattern: bool = Field(
        ..., description="Whether the password contains common patterns like dates"
    )
    password_tips: list[str] = Field(
        ..., description="Tips to improve the password security"
    )
    security_score: str = Field(
        ..., description="A letter grade (A-F) representing password security"
    )
    has_non_latin: bool = Field(
        False, description="Whether the password contains non-Latin characters"
    )
    scripts_used: list[str] = Field(
        [], description="The writing systems/scripts detected in the password (Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari, Bengali, Tamil, Telugu, Kannada, Malayalam, Thai, Japanese, Chinese, Korean, etc.)"
    )
    vulnerability_assessment: VulnerabilityAssessment = Field(
        ..., description="Assessment of the password's vulnerability to different attack types"
    )
    breach_info: BreachInfo = Field(
        default_factory=BreachInfo, description="Information about the password's presence in known data breaches"
    )
    hash_crack_times: Dict[str, HashTimeInfo] = Field(
        default_factory=dict, description="Crack time estimates for different hash algorithms using hashcat benchmark data"
    )
