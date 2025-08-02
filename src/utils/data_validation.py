"""
Module for password data validation.
"""
import sys
import unicodedata

from src.middleware.logger import logger
from src.middleware.exception import CustomException


def is_valid_password(text: str) -> int:
    """The is_valid_password function checks whether a given password meets
    certain criteria and returns an integer value indicating its validity.

    Args:
    ---
        text (str): The password to be validated.

    Returns:
    ---
        int: An integer value representing the validity of the password.
        It returns 1 if the password is valid, and 0 if it is not.
    """
    try:
        # Check length requirements
        if len(text) < 4 or len(text) > 64:
            logger.warning(f"Password length {len(text)} outside valid range (4-64)")
            return 0

        # Define Devanagari range explicitly
        devanagari_range = range(0x0900, 0x097F + 1)
        
        # Accept all Unicode letters, numbers and various special characters
        for i, char in enumerate(text):
            category = unicodedata.category(char)
            char_code = ord(char)
            
            # Check if it's Devanagari
            is_devanagari = char_code in devanagari_range
            
            # Allow all letters from any script (Lu = uppercase, Ll = lowercase, Lo = other letters like in many Asian scripts)
            # Allow all numbers (Nd = decimal digit)
            # Allow all symbols (Sc = currency, Sm = math, Sk = modifier, So = other symbols)
            # Allow all punctuation (Pc, Pd, Pe, Pf, Pi, Po, Ps = various punctuation categories)
            # Allow spaces (Zs = space)
            # Special case: allow Cf (format) category which includes soft hyphen and other invisible formatting
            # Additionally, explicitly check for Devanagari script
            if not (category.startswith('L') or  # Letter in any language/script
                    category.startswith('N') or  # Number in any script
                    category.startswith('S') or  # Symbols (including currency, math)
                    category.startswith('P') or  # Punctuation
                    category.startswith('Z') or  # Spaces
                    category.startswith('Cf') or # Format characters
                    is_devanagari or            # Explicitly check Devanagari
                    char in "!@#$%^&*. ~()_+={}[]|\\:;'\"<>/?`,`- "):  # Special chars
                
                # Additional debugging to help identify problematic characters
                try:
                    char_name = unicodedata.name(char)
                    char_hex = hex(ord(char))
                    script_name = "Unknown"
                    for range_name, ranges in {"Devanagari": [(0x0900, 0x097F)]}.items():
                        for start, end in ranges:
                            if start <= ord(char) <= end:
                                script_name = range_name
                                break
                    
                    logger.warning(f"Invalid character at position {i}: '{char}' ({char_name}, {char_hex}, category {category}, script {script_name})")
                except Exception as e:
                    logger.warning(f"Error identifying character: {str(e)}")
                    
                return 0
                
        return 1
    except Exception as error:
        raise CustomException(error, sys) from error
