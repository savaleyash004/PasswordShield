#!/usr/bin/env python
"""
Test script to verify Devanagari password support.
"""

import unicodedata
import sys
from src.utils.data_validation import is_valid_password
from src.api.utils import detect_scripts
from src.middleware.logger import logger

def test_devanagari_password(password):
    """Test a Devanagari password to see if it's properly accepted."""
    print(f"\nTesting password: {password}")
    print(f"Length: {len(password)}")
    
    # Check each character
    print("\nCharacter analysis:")
    for i, char in enumerate(password):
        code = ord(char)
        category = unicodedata.category(char)
        name = unicodedata.name(char, "Unknown")
        script = "Devanagari" if 0x0900 <= code <= 0x097F else "Other"
        print(f"  Char {i}: '{char}' - Code: {hex(code)}, Category: {category}, Name: {name}, Script: {script}")
    
    # Test validation
    valid = is_valid_password(password)
    print(f"\nValidation result: {'PASS' if valid else 'FAIL'}")
    
    # Test script detection
    has_non_latin, scripts = detect_scripts(password)
    print(f"Script detection: has_non_latin={has_non_latin}, scripts={scripts}")
    
    return valid

def main():
    """Run tests on several Devanagari passwords."""
    print("Devanagari Password Support Test")
    print("===============================")
    
    # Test cases
    test_passwords = [
        "अपनेसपनों",  # Pure Devanagari
        "अपने8सपनों",  # Devanagari with numbers
        "अपने8सपनोंK",  # Devanagari with numbers and Latin
        "अपने8सपनोंK&",  # Devanagari with numbers, Latin, and special chars
        "देवनागरी@2023"  # Devanagari with special chars and numbers
    ]
    
    results = []
    for password in test_passwords:
        result = test_devanagari_password(password)
        results.append((password, result))
    
    # Summary
    print("\n\nTest Summary:")
    print("=============")
    for password, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {password}")
    
    # Overall result
    if all(result for _, result in results):
        print("\n✅ All Devanagari passwords passed validation")
        return 0
    else:
        print("\n❌ Some Devanagari passwords failed validation")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 