"""
Hash Crack Time Estimation Module

This module estimates how long it would take to crack a password hash
using different attack methods (brute force, dictionary, etc.) and different hardware.
It integrates with the hashcat concepts for realistic estimates.
"""

import math
from typing import Dict, List, Tuple
import unicodedata

# Hashcat performance metrics for different hardware setups (hashes per second)
# These are approximate values for MD5 hash (real values depend on hardware & algorithm)
HASHCAT_PERFORMANCE = {
    'md5': {
        'cpu': 2_500_000,          # 2.5 million hashes per second on average CPU
        'gpu': 25_000_000_000,     # 25 billion hashes per second on high-end GPU
        'cluster': 100_000_000_000 # 100 billion hashes per second on a GPU cluster
    },
    'sha1': {
        'cpu': 1_200_000,
        'gpu': 8_500_000_000,
        'cluster': 40_000_000_000
    },
    'sha256': {
        'cpu': 550_000,
        'gpu': 3_600_000_000,
        'cluster': 15_000_000_000
    },
    'sha512': {
        'cpu': 200_000,
        'gpu': 1_200_000_000,
        'cluster': 6_000_000_000
    },
    'bcrypt': {
        'cpu': 20_000,
        'gpu': 100_000,
        'cluster': 500_000
    }
}

# Character sets for different complexity levels
CHARSET_SIZE = {
    'numeric': 10,            # 0-9
    'lowercase': 26,          # a-z
    'uppercase': 26,          # A-Z
    'alpha': 52,              # a-z, A-Z
    'alphanumeric': 62,       # a-z, A-Z, 0-9
    'ascii_symbols': 33,      # !@#$%^&*()_+-=[]{}|;:,.<>/?`~
    'ascii_printable': 95,    # All ASCII printable characters
    'unicode_basic': 128,     # Basic multilingual plane common characters
    'unicode_full': 65536     # Full Unicode plane
}

# Common time units for human-readable output
TIME_UNITS = [
    ('years', 60 * 60 * 24 * 365),
    ('months', 60 * 60 * 24 * 30),
    ('weeks', 60 * 60 * 24 * 7),
    ('days', 60 * 60 * 24),
    ('hours', 60 * 60),
    ('minutes', 60),
    ('seconds', 1)
]

def analyze_password_complexity(password: str) -> Dict:
    """
    Analyze the complexity of a password based on its characteristics
    
    Args:
        password: The password to analyze
        
    Returns:
        Dict: Analysis of password complexity
    """
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_numeric = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    # Check for non-ASCII characters
    has_non_ascii = any(ord(c) > 127 for c in password)
    
    # Identify which scripts are used
    scripts_used = set()
    for char in password:
        if char.isalpha():
            script_name = unicodedata.name(char).split()[0]
            scripts_used.add(script_name)
    
    # Estimate the character space size
    charset_size = 0
    if has_lowercase:
        charset_size += CHARSET_SIZE['lowercase']
    if has_uppercase:
        charset_size += CHARSET_SIZE['uppercase']
    if has_numeric:
        charset_size += CHARSET_SIZE['numeric']
    if has_special:
        charset_size += CHARSET_SIZE['ascii_symbols']
    if has_non_ascii:
        if len(scripts_used) == 1:
            charset_size += CHARSET_SIZE['unicode_basic']
        else:
            charset_size += CHARSET_SIZE['unicode_full']
    
    # Ensure minimum charset size
    charset_size = max(charset_size, 10)
    
    # Generate summary stats
    result = {
        'length': len(password),
        'has_lowercase': has_lowercase,
        'has_uppercase': has_uppercase,
        'has_numeric': has_numeric,
        'has_special': has_special, 
        'has_non_ascii': has_non_ascii,
        'scripts_used': list(scripts_used),
        'charset_size': charset_size,
        'complexity_level': get_complexity_level(password, charset_size)
    }
    
    return result

def get_complexity_level(password: str, charset_size: int) -> str:
    """
    Determine the complexity level of a password
    
    Args:
        password: The password to analyze
        charset_size: Size of the character set used
        
    Returns:
        str: Complexity level (Very Low, Low, Medium, High, Very High)
    """
    length = len(password)
    
    # Base entropy estimation
    entropy = length * math.log2(charset_size)
    
    if entropy < 28:
        return "Very Low"
    elif entropy < 36:
        return "Low"
    elif entropy < 60:
        return "Medium"
    elif entropy < 80:
        return "High"
    else:
        return "Very High"

def format_time(seconds: float) -> str:
    """
    Format time in seconds to a human-readable string
    
    Args:
        seconds: Time in seconds
        
    Returns:
        str: Human-readable time string
    """
    if seconds < 1:
        return "less than a second"
        
    if seconds > 1e20:  # If time is astronomical
        return "heat death of the universe"
        
    for unit, unit_seconds in TIME_UNITS:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            if value < 2:
                # Handle singular (1 day vs 2 days)
                unit = unit[:-1]
            return f"{value:.1f} {unit}"
            
    return f"{seconds:.1f} seconds"

def estimate_crack_time(password: str, hash_type: str = 'bcrypt') -> Dict:
    """
    Estimate the time it would take to crack a password using different methods
    
    Args:
        password: The password to analyze
        hash_type: Type of hash algorithm (md5, sha1, sha256, sha512, bcrypt)
        
    Returns:
        Dict: Estimated crack times for different attack methods and hardware
    """
    complexity = analyze_password_complexity(password)
    length = complexity['length']
    charset_size = complexity['charset_size']
    
    # Brute force complexity = charset_size ^ length
    # This is the worst-case scenario (trying all possibilities)
    brute_force_combinations = charset_size ** length
    
    # Dictionary attack estimation
    # For dictionary attacks, we simulate the likelihood based on complexity characteristics
    dictionary_factor = 1.0
    
    # More complex passwords are less likely to be in dictionaries
    if complexity['has_lowercase']:
        dictionary_factor *= 0.8
    if complexity['has_uppercase']:
        dictionary_factor *= 0.6
    if complexity['has_numeric']:
        dictionary_factor *= 0.7
    if complexity['has_special']:
        dictionary_factor *= 0.5
    if complexity['has_non_ascii']:
        dictionary_factor *= 0.3
        
    # Longer passwords have more variations
    dictionary_factor *= (0.9 ** (length - 8)) if length > 8 else 1.0
    
    # Dictionary attack assumes checking against ~10 billion common passwords/variations
    dictionary_combinations = 10_000_000_000 * dictionary_factor
    
    # Targeted attack (combines knowledge of user with common patterns)
    # Simulates an attacker with some knowledge of the user or organization
    targeted_combinations = brute_force_combinations * 0.001  # 0.1% of brute force
    
    # Ensure minimum values
    dictionary_combinations = max(1000, dictionary_combinations)
    targeted_combinations = max(10000, targeted_combinations)
    
    # Calculate crack times for different hardware setups
    crack_times = {}
    
    for hardware, hashes_per_second in HASHCAT_PERFORMANCE[hash_type].items():
        brute_force_time = brute_force_combinations / hashes_per_second
        dictionary_time = dictionary_combinations / hashes_per_second
        targeted_time = targeted_combinations / hashes_per_second
        
        crack_times[hardware] = {
            'brute_force': {
                'seconds': brute_force_time,
                'human_readable': format_time(brute_force_time)
            },
            'dictionary': {
                'seconds': dictionary_time,
                'human_readable': format_time(dictionary_time)
            },
            'targeted': {
                'seconds': targeted_time,
                'human_readable': format_time(targeted_time)
            }
        }
    
    return {
        'complexity': complexity,
        'crack_times': crack_times
    }

def get_risk_level(password: str) -> str:
    """
    Get the overall risk level based on crack time estimates
    
    Args:
        password: The password to analyze
        
    Returns:
        str: Risk level (Critical, High, Medium, Low, Very Low)
    """
    estimate = estimate_crack_time(password)
    
    # Look at GPU dictionary attack time as the reference
    dictionary_seconds = estimate['crack_times']['gpu']['dictionary']['seconds']
    
    if dictionary_seconds < 60:  # Less than a minute
        return "Critical"
    elif dictionary_seconds < 60 * 60 * 24:  # Less than a day
        return "High"
    elif dictionary_seconds < 60 * 60 * 24 * 30:  # Less than a month
        return "Medium"
    elif dictionary_seconds < 60 * 60 * 24 * 365:  # Less than a year
        return "Low"
    else:
        return "Very Low"

def format_crack_time_summary(password: str) -> str:
    """
    Create a human-readable summary of password crack time estimates
    
    Args:
        password: The password to analyze
        
    Returns:
        str: A human-readable summary
    """
    estimate = estimate_crack_time(password)
    complexity = estimate['complexity']
    risk_level = get_risk_level(password)
    
    summary = [
        f"Password Crack Time Analysis (Risk Level: {risk_level})",
        f"Length: {complexity['length']} characters",
        f"Character set: {complexity['charset_size']} unique characters",
        f"Complexity: {complexity['complexity_level']}",
        "",
        "Estimated time to crack:"
    ]
    
    # GPU times are the most relevant for modern attacks
    gpu_times = estimate['crack_times']['gpu']
    summary.append("  Using high-end GPU:")
    summary.append(f"    • Brute force attack: {gpu_times['brute_force']['human_readable']}")
    summary.append(f"    • Dictionary attack: {gpu_times['dictionary']['human_readable']}")
    summary.append(f"    • Targeted attack: {gpu_times['targeted']['human_readable']}")
    
    # Add script information if non-ASCII characters are present
    if complexity['has_non_ascii']:
        scripts = ", ".join(complexity['scripts_used'])
        summary.append(f"\nMultiple scripts detected: {scripts}")
        summary.append("Non-ASCII characters significantly increase crack time.")
    
    return "\n".join(summary)

# Example usage
if __name__ == "__main__":
    test_passwords = [
        "password123",
        "qwerty",
        "P@s5w0rd!2023",
        "हिन्दी123",
        "γεια123",
        "मराठी2023",
        "SuperSecureP@ssw0rd!",
        "Tröödlå123$Væry&Str0ng"
    ]
    
    print("Hash Crack Time Estimates:")
    print("-" * 70)
    for pwd in test_passwords:
        print(f"Password: {pwd}")
        print(format_crack_time_summary(pwd))
        print("-" * 70) 