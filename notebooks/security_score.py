"""
Security Score and Password Tips Module

This module calculates a user-friendly security score for passwords
and provides actionable tips for improving password security.
"""

import re
from typing import Dict, List, Tuple

# Import our other modules (relative imports for notebook context)
try:
    from pattern_detection import check_advanced_patterns
    from hash_crack_times import analyze_password_complexity, get_risk_level
    from breach_detection import get_breach_recommendations
except ImportError:
    # If importing as standalone
    pass

# Define scoring weights for different password characteristics
SCORE_WEIGHTS = {
    'length': 0.25,
    'complexity': 0.25,
    'patterns': 0.2,
    'breach': 0.3
}

# Common password problems and corresponding tips
SECURITY_TIPS = {
    'length': [
        {'condition': lambda pwd: len(pwd) < 8, 
         'tip': "Your password is too short. Use at least 12 characters for better security."},
        {'condition': lambda pwd: len(pwd) < 12, 
         'tip': "Consider using a longer password (12+ characters) for stronger security."}
    ],
    'character_mix': [
        {'condition': lambda pwd: not any(c.isupper() for c in pwd),
         'tip': "Add uppercase letters (A-Z) to increase complexity."},
        {'condition': lambda pwd: not any(c.islower() for c in pwd),
         'tip': "Add lowercase letters (a-z) to increase complexity."},
        {'condition': lambda pwd: not any(c.isdigit() for c in pwd),
         'tip': "Add numbers (0-9) to increase complexity."},
        {'condition': lambda pwd: not any(not c.isalnum() for c in pwd),
         'tip': "Add special characters (!@#$%^&*) to increase complexity."}
    ],
    'patterns': [
        {'condition': lambda pwd: check_advanced_patterns(pwd)['keyboard_pattern'],
         'tip': "Avoid keyboard patterns like 'qwerty' or 'asdfgh'."},
        {'condition': lambda pwd: check_advanced_patterns(pwd)['sequential_pattern'],
         'tip': "Avoid sequential patterns like '12345' or 'abcde'."},
        {'condition': lambda pwd: check_advanced_patterns(pwd)['repetitive_pattern'],
         'tip': "Avoid repetitive patterns like 'abcabc' or 'passpass'."}
    ],
    'common_patterns': [
        {'condition': lambda pwd: re.search(r'\b(19|20)\d{2}\b', pwd),
         'tip': "Avoid using years in your password - they're easy to guess."},
        {'condition': lambda pwd: 'password' in pwd.lower() or 'pass' in pwd.lower(),
         'tip': "Avoid using the word 'password' in your password."},
        {'condition': lambda pwd: 'admin' in pwd.lower() or 'root' in pwd.lower(),
         'tip': "Avoid using common words like 'admin' or 'root'."},
        {'condition': lambda pwd: len(set(pwd)) < len(pwd) * 0.5,
         'tip': "Your password has too many repeated characters."}
    ],
    'general': [
        {'condition': lambda pwd: True,  # Always suggest using a password manager
         'tip': "Use a password manager to generate and store strong, unique passwords."},
        {'condition': lambda pwd: len(pwd) > 0,  # Always suggest not reusing passwords
         'tip': "Use a unique password for each account - never reuse passwords."}
    ]
}

def calculate_length_score(password: str) -> float:
    """
    Calculate a score based on password length
    
    Args:
        password: The password to analyze
        
    Returns:
        float: Score between 0-1
    """
    length = len(password)
    
    # Ideal length is 16+ characters
    if length >= 16:
        return 1.0
    elif length >= 12:
        return 0.8
    elif length >= 8:
        return 0.5
    elif length >= 6:
        return 0.3
    else:
        return 0.1

def calculate_complexity_score(password: str) -> float:
    """
    Calculate a score based on character complexity
    
    Args:
        password: The password to analyze
        
    Returns:
        float: Score between 0-1
    """
    # Use our complexity analysis from hash_crack_times
    complexity_data = analyze_password_complexity(password)
    
    # Calculate basic complexity score
    score = 0.0
    
    # Character type diversity
    if complexity_data['has_lowercase']:
        score += 0.2
    if complexity_data['has_uppercase']:
        score += 0.2
    if complexity_data['has_numeric']:
        score += 0.2
    if complexity_data['has_special']:
        score += 0.2
    if complexity_data['has_non_ascii']:
        score += 0.2
        
    # Adjust score based on complexity level
    complexity_level = complexity_data['complexity_level']
    if complexity_level == 'Very High':
        score = min(1.0, score * 1.2)
    elif complexity_level == 'High':
        score = min(1.0, score * 1.1)
    elif complexity_level == 'Low':
        score *= 0.8
    elif complexity_level == 'Very Low':
        score *= 0.6
        
    return score

def calculate_pattern_score(password: str) -> float:
    """
    Calculate a score based on pattern detection
    Lower score for passwords with easily recognizable patterns
    
    Args:
        password: The password to analyze
        
    Returns:
        float: Score between 0-1
    """
    # Use our pattern detection
    patterns = check_advanced_patterns(password)
    
    # Start with perfect score and deduct for each pattern
    score = 1.0
    
    if patterns['keyboard_pattern']:
        score -= 0.4
    if patterns['sequential_pattern']:
        score -= 0.3
    if patterns['repetitive_pattern']:
        score -= 0.4
        
    # Check for years (common pattern)
    if re.search(r'\b(19|20)\d{2}\b', password):
        score -= 0.2
        
    # Check for common words
    common_words = ['password', 'admin', 'user', 'login', 'welcome']
    for word in common_words:
        if word in password.lower():
            score -= 0.3
            break
            
    # Ensure minimum score of 0.1
    return max(0.1, score)

def calculate_breach_score(password: str) -> float:
    """
    Calculate a score based on breach detection
    
    Args:
        password: The password to analyze
        
    Returns:
        float: Score between 0-1 (0 if breached, 1 if not)
    """
    # Check if password appears in breaches
    breach_info = get_breach_recommendations(password)
    
    # If found in a breach, return 0, otherwise return 1
    if breach_info['found_in_breach']:
        # More breaches = lower score
        breach_count = breach_info['breach_count']
        if breach_count > 2:
            return 0.0
        elif breach_count == 2:
            return 0.1
        else:
            return 0.2
    else:
        return 1.0

def calculate_security_score(password: str) -> Dict:
    """
    Calculate an overall security score for a password
    
    Args:
        password: The password to analyze
        
    Returns:
        Dict: Dictionary with overall score and component scores
    """
    # Calculate component scores
    length_score = calculate_length_score(password)
    complexity_score = calculate_complexity_score(password)
    pattern_score = calculate_pattern_score(password)
    breach_score = calculate_breach_score(password)
    
    # Calculate weighted score
    weighted_score = (
        length_score * SCORE_WEIGHTS['length'] +
        complexity_score * SCORE_WEIGHTS['complexity'] +
        pattern_score * SCORE_WEIGHTS['patterns'] +
        breach_score * SCORE_WEIGHTS['breach']
    )
    
    # Convert to 0-100 scale and round to nearest integer
    overall_score = round(weighted_score * 100)
    
    # Ensure score is between 0-100
    overall_score = max(0, min(100, overall_score))
    
    # Get risk level from hash_crack_times module
    risk_level = get_risk_level(password)
    
    return {
        'overall_score': overall_score,
        'score_components': {
            'length': length_score,
            'complexity': complexity_score,
            'patterns': pattern_score,
            'breach': breach_score
        },
        'risk_level': risk_level
    }

def get_password_tips(password: str) -> List[str]:
    """
    Generate actionable tips for improving password security
    
    Args:
        password: The password to analyze
        
    Returns:
        List[str]: List of security improvement tips
    """
    tips = []
    
    # Check each category of tips
    for category, checks in SECURITY_TIPS.items():
        for check in checks:
            if check['condition'](password):
                tips.append(check['tip'])
    
    # If there are too many tips, prioritize them
    if len(tips) > 5:
        # Remove general tips if there are specific issues
        tips = [tip for tip in tips if tip != SECURITY_TIPS['general'][0]['tip']]
        tips = tips[:4]  # Limit to top 4 specific tips
        # Add back the password manager recommendation
        tips.append(SECURITY_TIPS['general'][0]['tip'])
    
    return tips

def get_security_summary(password: str) -> Dict:
    """
    Get comprehensive security analysis for a password
    
    Args:
        password: The password to analyze
        
    Returns:
        Dict: Complete security analysis including score and tips
    """
    score_data = calculate_security_score(password)
    tips = get_password_tips(password)
    
    # Convert score to word rating
    score = score_data['overall_score']
    if score >= 90:
        rating = 'Excellent'
    elif score >= 70:
        rating = 'Good'
    elif score >= 50:
        rating = 'Fair'
    elif score >= 30:
        rating = 'Weak'
    else:
        rating = 'Very Weak'
        
    # Add letter grade (like school grades)
    if score >= 90:
        grade = 'A+'
    elif score >= 85:
        grade = 'A'
    elif score >= 80:
        grade = 'A-'
    elif score >= 75:
        grade = 'B+'
    elif score >= 70:
        grade = 'B'
    elif score >= 65:
        grade = 'B-'
    elif score >= 60:
        grade = 'C+'
    elif score >= 50:
        grade = 'C'
    elif score >= 40:
        grade = 'D'
    else:
        grade = 'F'
        
    return {
        'score': score,
        'rating': rating,
        'grade': grade,
        'risk_level': score_data['risk_level'],
        'score_components': score_data['score_components'],
        'improvement_tips': tips
    }

def format_security_summary(password: str) -> str:
    """
    Create a human-readable security summary
    
    Args:
        password: The password to analyze
        
    Returns:
        str: Formatted security summary
    """
    summary = get_security_summary(password)
    
    output = [
        f"Security Score: {summary['score']}/100 ({summary['rating']}, Grade: {summary['grade']})",
        f"Risk Level: {summary['risk_level']}",
        "",
        "Score Breakdown:",
        f"  • Length: {summary['score_components']['length']*100:.0f}/100",
        f"  • Complexity: {summary['score_components']['complexity']*100:.0f}/100",
        f"  • Pattern Avoidance: {summary['score_components']['patterns']*100:.0f}/100",
        f"  • Breach Status: {summary['score_components']['breach']*100:.0f}/100",
        "",
        "Improvement Tips:"
    ]
    
    for i, tip in enumerate(summary['improvement_tips'], 1):
        output.append(f"  {i}. {tip}")
        
    return "\n".join(output)

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
    
    print("Password Security Score and Tips:")
    print("-" * 70)
    for pwd in test_passwords:
        print(f"Password: {pwd}")
        print(format_security_summary(pwd))
        print("-" * 70) 