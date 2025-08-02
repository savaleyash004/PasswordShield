"""
Data Breach Information Module

This module provides functions to check if a password appears in known data breaches
and provides recommendations based on the findings.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple, Union
import random

# Simulated database of breached passwords - in a real implementation,
# this would be an API call to a service like "Have I Been Pwned" or a local database
# For demonstration, we'll use a small set of very common passwords
COMMON_BREACHED_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", 
    "1234567", "111111", "1234567890", "123123", "abc123", "1234", 
    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", 
    "zaq12wsx", "dragon", "sunshine", "princess", "letmein",
    "monkey", "welcome", "login", "admin", "qwertyuiop"
}

# Simulated breach database with breach names and dates
# In a real implementation, this would come from an API or database
BREACH_DATABASE = {
    "linkedin": {"name": "LinkedIn", "date": "2012-06-05", "accounts": 164611595},
    "adobe": {"name": "Adobe", "date": "2013-10-04", "accounts": 152445165},
    "myspace": {"name": "MySpace", "date": "2008-07-01", "accounts": 359420698},
    "tumblr": {"name": "Tumblr", "date": "2013-02-28", "accounts": 65469298},
    "gmail": {"name": "Gmail", "date": "2014-09-09", "accounts": 4937376},
}

def hash_password(password: str) -> str:
    """
    Create a SHA-1 hash of the password (for demonstration only).
    In production, use more secure methods and k-anonymity.
    
    Args:
        password: The password to hash
        
    Returns:
        str: SHA-1 hash of the password
    """
    # Note: In a real implementation, we would only send the first 5 characters
    # of the hash to a service like HIBP, using k-anonymity
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()


def check_password_in_breaches(password: str) -> Tuple[bool, List[Dict]]:
    """
    Check if a password appears in known data breaches.
    
    Args:
        password: The password to check
        
    Returns:
        Tuple[bool, List[Dict]]: A tuple containing a boolean indicating if the password 
                                was found in breaches, and a list of breach details
    """
    # In a real implementation, this would call an API service
    # For demonstration, we'll check against our small set of known breached passwords
    
    # Simple simulation - check if password is in our common list
    found = password.lower() in COMMON_BREACHED_PASSWORDS
    
    # If found, generate some simulated breach data
    breaches = []
    if found:
        # Randomly select 1-3 breaches from our database
        breach_count = random.randint(1, 3)
        selected_breaches = random.sample(list(BREACH_DATABASE.keys()), min(breach_count, len(BREACH_DATABASE)))
        
        for breach_id in selected_breaches:
            breach_info = BREACH_DATABASE[breach_id].copy()
            # Add some randomization to the breach counts
            breach_info["accounts"] = breach_info["accounts"] + random.randint(-1000000, 1000000)
            breaches.append(breach_info)
    
    return found, breaches


def get_breach_recommendations(password: str) -> Dict:
    """
    Get breach information and recommendations for a password.
    
    Args:
        password: The password to check
        
    Returns:
        Dict: Information about breaches and recommendations
    """
    is_breached, breach_details = check_password_in_breaches(password)
    
    result = {
        "found_in_breach": is_breached,
        "breach_count": len(breach_details),
        "breach_details": breach_details,
        "recommendations": []
    }
    
    # Add appropriate recommendations
    if is_breached:
        result["recommendations"].extend([
            "Change this password immediately on all sites where you use it.",
            "Use a unique password for each account.",
            "Consider using a password manager to generate and store strong, unique passwords."
        ])
        
        # If it appears in multiple breaches, add stronger warning
        if len(breach_details) > 1:
            result["recommendations"].append(
                f"This password appeared in {len(breach_details)} different data breaches. "
                f"It is extremely vulnerable to dictionary attacks."
            )
    else:
        result["recommendations"].append(
            "No breaches found, but still ensure you use unique passwords for each account."
        )
    
    return result


def format_breach_summary(breach_info: Dict) -> str:
    """
    Create a human-readable summary of breach information.
    
    Args:
        breach_info: Dictionary containing breach information
        
    Returns:
        str: A human-readable summary
    """
    if not breach_info["found_in_breach"]:
        return "Good news! This password was not found in any known data breaches."
    
    # Create summary for breached password
    breach_count = breach_info["breach_count"]
    
    summary = [
        f"⚠️ WARNING: This password was found in {breach_count} known data breach{'es' if breach_count > 1 else ''}.",
        "Breach details:"
    ]
    
    # Add details for each breach
    for breach in breach_info["breach_details"]:
        summary.append(
            f"- {breach['name']} ({breach['date']}): {breach['accounts']:,} accounts affected"
        )
    
    # Add recommendations
    summary.append("\nRecommendations:")
    for i, recommendation in enumerate(breach_info["recommendations"], 1):
        summary.append(f"{i}. {recommendation}")
    
    return "\n".join(summary)


# Example usage
if __name__ == "__main__":
    test_passwords = [
        "password123",
        "qwerty",
        "P@s5w0rd!2023",
        "unique_very_strong_password"
    ]
    
    print("Data Breach Information Test:")
    print("-" * 70)
    for pwd in test_passwords:
        breach_info = get_breach_recommendations(pwd)
        print(f"Password: {pwd}")
        print(format_breach_summary(breach_info))
        print("-" * 70) 