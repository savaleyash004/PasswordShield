"""This module defines a FastAPI endpoint for predicting the strength of a given
password using a trained machine learning model and a data pipeline."""

import sys
import unicodedata

from fastapi import HTTPException

from src.api.schema import (
    GenerateRequest,
    GenerateResponse,
    PredictionRequest,
    PredictionResponse,
)
from src.api.utils import (
    assess_password_vulnerability,
    calc_class_strength,
    calc_entropy,
    calc_strength,
    check_password_breaches,
    detect_scripts,
    display_time,
    entropy_to_crack_time,
    generate_password,
    HASHCAT_MODES,
)
from src.middleware.exception import CustomException
from src.middleware.logger import logger
from src.utils.data_validation import is_valid_password
from src.utils.feature_extraction import PatternTransform


def detect_pattern(password: str) -> bool:
    """Detect if the password contains common patterns.
    
    Args:
        password (str): The password to check.
        
    Returns:
        bool: True if pattern detected, False otherwise.
    """
    pattern_transformer = PatternTransform()
    result = pattern_transformer._patternTransform(password)
    return bool(result)

def generate_password_tips(password: str, strength: float) -> list[str]:
    """Generate tips to improve password security.
    
    Args:
        password (str): The password to analyze.
        strength (float): The strength of the password.
        
    Returns:
        list[str]: A list of tips to improve the password.
    """
    tips = []
    
    if len(password) < 12:
        tips.append("Use at least 12 characters for your password")
    
    if not any(c.isupper() for c in password):
        tips.append("Include uppercase letters (A-Z)")
    
    if not any(c.islower() for c in password):
        tips.append("Include lowercase letters (a-z)")
    
    if not any(c.isdigit() for c in password):
        tips.append("Include numbers (0-9)")
    
    if not any(c in "!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,`- " for c in password):
        tips.append("Include special characters (e.g., !@#$%^&* and others)")
    
    if detect_pattern(password):
        tips.append("Avoid common patterns like dates or keyboard sequences")
    
    if len(set(password)) < len(password) / 2:
        tips.append("Use more unique characters, avoid repetition")
    
    # If we have a strong password but still want to offer a tip
    if not tips and strength < 0.9:
        tips.append("For even stronger security, increase length and complexity")
    
    if not tips:
        tips.append("Excellent password! Keep it secure.")
    
    return tips

def calculate_security_score(strength: float) -> str:
    """Calculate a letter grade security score based on strength.
    
    Args:
        strength (float): The strength of the password.
        
    Returns:
        str: A letter grade from A to F.
    """
    if strength >= 0.9:
        return "A"
    elif strength >= 0.8:
        return "B"
    elif strength >= 0.7:
        return "C"
    elif strength >= 0.6:
        return "D"
    elif strength >= 0.4:
        return "E"
    else:
        return "F"

def password_strength_component(
    request: PredictionRequest,
) -> PredictionResponse:
    """
    Predict the strength of a given password.

    Args:
        request (PredictionRequest): The request containing the password.

    Returns:
        PredictionResponse: The response containing the password ,
        strength prediction and its strength class.

    Raises:
        HTTPException: If the password is invalid or any other custom exception
        occurs.
    """
    try:
        logger.info("Called predict function")

        password = request.password
        
        # Debug password info
        debug_info = []
        for i, char in enumerate(password):
            try:
                cat = unicodedata.category(char)
                char_code = ord(char)
                script_range = ""
                if 0x0900 <= char_code <= 0x097F:
                    script_range = "Devanagari"
                debug_info.append(f"Char '{char}' at pos {i}: code={hex(char_code)}, cat={cat}, script={script_range}")
            except:
                debug_info.append(f"Char at pos {i}: error getting info")
        
        logger.info(f"Password analysis: {', '.join(debug_info)}")

        validation_result = is_valid_password(password)
        if validation_result == 0:
            if len(password) < 4:
                logger.error("400 Bad Request: Invalid too short password")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid too short password:"
                    " Length of the password should be greater then 3",
                )
            if len(password) > 64:
                logger.error("400 Bad Request: Invalid password length")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid password length:"
                    " Length of the password should be lesser then 64",
                )
                
            # Check specifically for Devanagari characters
            has_devanagari = any(0x0900 <= ord(c) <= 0x097F for c in password)
            if has_devanagari:
                logger.error("Password contains Devanagari but validation failed")
                
            logger.error("400 Bad Request: Invalid password characters")
            raise HTTPException(
                status_code=400,
                detail="Invalid password characters: "
                "Valid values for passwords include numerals, capital letters, "
                "lowercase letters, and a wide range of special characters including "
                "!, @, #, $, %, ^, &, *, ., ~, (), _, +, =, {}, [], |, \\, :, ;, ', \", <>, /, ?, `, `, -, and space. "
                "Non-Latin scripts for various languages are also supported.",
            )

        try:
            strength = calc_strength(password)
            class_strength = calc_class_strength(strength, password)
            entropy = calc_entropy(password)
            
            # Calculate crack times for different hash algorithms
            hash_types = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'ntlm', 'argon2id', 'scrypt']
            crack_times = {}
            for hash_type in hash_types:
                crack_time_sec = entropy_to_crack_time(entropy, hash_type)
                crack_times[hash_type] = {
                    'seconds': round(crack_time_sec, 3),
                    'display': display_time(crack_time_sec)
                }
                
            # Use sha256 as the default crack time for backward compatibility
            crack_time = crack_times.get('sha256', {}).get('seconds', 0)
            crack_time_display = crack_times.get('sha256', {}).get('display', 'Unknown')
            
            # Calculate new fields
            has_pattern = detect_pattern(password)
            password_tips = generate_password_tips(password, strength)
            security_score = calculate_security_score(strength)
            
            # Detect scripts used in the password
            has_non_latin, scripts_used = detect_scripts(password)
            logger.info(f"Scripts detected: {scripts_used}")
            
            # Perform vulnerability assessment
            vulnerability_assessment = assess_password_vulnerability(password, strength, entropy)
            logger.info(f"Vulnerability assessment: {vulnerability_assessment}")
            
            # Check for password breaches
            breach_info = check_password_breaches(password)
            logger.info(f"Breach check: {breach_info}")
            
            # Log detailed assessment for debugging
            for attack_type, details in vulnerability_assessment.items():
                logger.info(f"Attack type: {attack_type}, Risk: {details.get('risk')}, Description: {details.get('description')}")
            
            # Validate vulnerability assessment structure
            expected_keys = ["dictionary_attack", "brute_force_attack", "hybrid_attack", 
                           "rainbow_table_attack", "table_attack"]
            
            for key in expected_keys:
                if key not in vulnerability_assessment:
                    logger.warning(f"Missing expected vulnerability key: {key}")
                    # Add default entry to keep API consistent
                    vulnerability_assessment[key] = {
                        "risk": "unknown",
                        "description": "Assessment not available"
                    }

        except Exception as error:
            logger.error(f"Error during password analysis: {str(error)}")
            raise HTTPException(status_code=500, detail=str(error)) from error

        return PredictionResponse(
            password=password,
            length=len(password),
            strength=strength,
            class_strength=class_strength,
            entropy=round(entropy, 3),
            crack_time_sec=round(crack_time, 3),
            crack_time=crack_time_display,
            has_pattern=has_pattern,
            password_tips=password_tips,
            security_score=security_score,
            has_non_latin=has_non_latin,
            scripts_used=scripts_used,
            vulnerability_assessment=vulnerability_assessment,
            breach_info=breach_info,
            hash_crack_times=crack_times
        )
    except CustomException as error:
        logger.error(error, sys)
        raise HTTPException(status_code=500, detail=str(error)) from error


def generate_strong_password(
    request: GenerateRequest,
) -> GenerateResponse:
    """Generate a strong password using numerals, letters, and specific
    special characters. When non-Latin characters are included, it can use
    Cyrillic, Greek, Chinese, and Devanagari (Hindi/Marathi) scripts.

    Args:
        request (GenerateRequest): The request containing the length of the
        generated password and whether to include non-Latin characters.

    Returns:
        GenerateResponse: The response containing the generated password.
    """
    try:
        logger.info("Called generate function")

        length = request.length
        include_non_latin = request.include_non_latin

        if length <= 12:
            logger.error("400 Bad Request: Invalid too short password")
            raise HTTPException(
                status_code=400,
                detail="Invalid too short password:"
                " Length of the password should be greater then 12",
            )
        if length > 64:
            logger.error("400 Bad Request: Invalid password length")
            raise HTTPException(
                status_code=400,
                detail="Invalid password length:"
                " Length of the password should be lesser then 64",
            )

        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                password = generate_password(length, include_non_latin)
                strength = calc_strength(password)

                if strength > 0.6:
                    class_strength = calc_class_strength(strength, password)
                    entropy = calc_entropy(password)
                    
                    # Calculate crack times for different hash algorithms
                    hash_types = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'ntlm', 'argon2id', 'scrypt']
                    crack_times = {}
                    for hash_type in hash_types:
                        crack_time_sec = entropy_to_crack_time(entropy, hash_type)
                        crack_times[hash_type] = {
                            'seconds': round(crack_time_sec, 3),
                            'display': display_time(crack_time_sec)
                        }
                        
                    # Use sha256 as the default crack time for backward compatibility
                    crack_time = crack_times.get('sha256', {}).get('seconds', 0)
                    crack_time_display = crack_times.get('sha256', {}).get('display', 'Unknown')

                    # Add new fields calculation for the generated password
                    has_pattern = detect_pattern(password)
                    password_tips = generate_password_tips(password, strength)
                    security_score = calculate_security_score(strength)
                    
                    # Detect scripts used in the password
                    has_non_latin, scripts_used = detect_scripts(password)
                    
                    # Perform vulnerability assessment
                    vulnerability_assessment = assess_password_vulnerability(password, strength, entropy)
                    logger.info(f"Vulnerability assessment completed for generated password")
                    
                    # Validate vulnerability assessment structure
                    expected_keys = ["dictionary_attack", "brute_force_attack", "hybrid_attack", 
                                   "rainbow_table_attack", "table_attack"]
                    
                    for key in expected_keys:
                        if key not in vulnerability_assessment:
                            logger.warning(f"Missing expected vulnerability key: {key}")
                            # Add default entry to keep API consistent
                            vulnerability_assessment[key] = {
                                "risk": "unknown",
                                "description": "Assessment not available"
                            }
                    
                    # Check for password breaches
                    breach_info = check_password_breaches(password)
                    logger.info(f"Generated password breach check: {breach_info}")
                    
                    logger.info("200 OK: Password generated successfully")

                    return GenerateResponse(
                        password=password,
                        length=len(password),
                        strength=strength,
                        class_strength=class_strength,
                        entropy=round(entropy, 3),
                        crack_time_sec=round(crack_time, 3),
                        crack_time=crack_time_display,
                        has_pattern=has_pattern,
                        password_tips=password_tips,
                        security_score=security_score,
                        has_non_latin=has_non_latin,
                        scripts_used=scripts_used,
                        vulnerability_assessment=vulnerability_assessment,
                        breach_info=breach_info,
                        hash_crack_times=crack_times
                    )
                    
            except Exception as error:
                logger.error(f"Attempt {attempt+1} failed: {error}")
                
        logger.error("500 Internal Server Error: Failed to generate a strong password")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate a strong password after multiple attempts. Please try again.",
        )
    except CustomException as error:
        logger.error(error, sys)
        raise HTTPException(status_code=500, detail=str(error)) from error
