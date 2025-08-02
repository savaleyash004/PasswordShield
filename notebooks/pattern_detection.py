"""
Advanced Pattern Detection for Multilingual Passwords

This module provides functions for detecting various patterns in passwords,
including keyboard patterns, sequential patterns, and repetitive patterns
across multiple languages and scripts.
"""

import re
import unicodedata
from typing import Dict, List, Tuple

# Define keyboard layouts for different languages
KEYBOARD_LAYOUTS = {
    # English QWERTY
    'en': {
        'rows': [
            '`1234567890-=',
            'qwertyuiop[]\\',
            'asdfghjkl;\'"',
            'zxcvbnm,./'
        ],
        'adjacency': {}  # Will be populated
    },
    # Devanagari (Hindi/Marathi)
    'hi': {
        'rows': [
            'ॊौैाीूबहगदजड़ॉ',
            'ोेिुपरकतचट',
            'ंमनवलस,.य',
            'अभशख़्ध'
        ],
        'adjacency': {}
    },
    # Greek
    'el': {
        'rows': [
            '`1234567890-=',
            ';ςερτυθιοπ[]\\',
            'ασδφγηξκλ΄\'"',
            'ζχψωβνμ,./'
        ],
        'adjacency': {}
    },
    # Chinese Pinyin
    'zh': {
        'rows': [
            '`1234567890-=',
            'qwertyuiop[]\\',
            'asdfghjkl;\'"',
            'zxcvbnm,./'
        ],
        'adjacency': {}
    }
}

# Build adjacency maps for each keyboard layout
for lang, layout in KEYBOARD_LAYOUTS.items():
    rows = layout['rows']
    adjacency = {}
    
    # Build adjacency map for the keyboard layout
    for i, row in enumerate(rows):
        for j, char in enumerate(row):
            adjacent_chars = []
            
            # Characters to the left and right
            if j > 0:
                adjacent_chars.append(row[j-1])
            if j < len(row) - 1:
                adjacent_chars.append(row[j+1])
                
            # Characters above and below
            if i > 0 and j < len(rows[i-1]):
                adjacent_chars.append(rows[i-1][j])
            if i < len(rows) - 1 and j < len(rows[i+1]):
                adjacent_chars.append(rows[i+1][j])
                
            adjacency[char] = adjacent_chars
    
    KEYBOARD_LAYOUTS[lang]['adjacency'] = adjacency


def detect_keyboard_pattern(password: str, min_length: int = 3) -> bool:
    """
    Detect if a password contains keyboard pattern walks
    Works with multiple keyboard layouts
    
    Args:
        password: The password to check
        min_length: Minimum length of pattern to detect
        
    Returns:
        bool: True if a keyboard pattern is detected
    """
    if len(password) < min_length:
        return False
        
    # Try to detect keyboard patterns in each layout
    for lang, layout in KEYBOARD_LAYOUTS.items():
        adjacency = layout['adjacency']
        
        # Check for horizontal, vertical or diagonal patterns
        for i in range(len(password) - min_length + 1):
            substring = password[i:i+min_length]
            
            # Check if characters are adjacent on keyboard
            is_pattern = True
            for j in range(len(substring) - 1):
                current_char = substring[j].lower()
                next_char = substring[j+1].lower()
                
                if current_char not in adjacency or next_char not in adjacency[current_char]:
                    is_pattern = False
                    break
                    
            if is_pattern:
                return True
                
    return False


def detect_repetitive_pattern(password: str) -> bool:
    """
    Detect if password contains repetitive patterns
    
    Args:
        password: The password to check
        
    Returns:
        bool: True if repetitive pattern is detected
    """
    # Check for repeated substrings
    password = password.lower()
    n = len(password)
    
    # Check for patterns of length 2 to n/2
    for pattern_len in range(2, n // 2 + 1):
        for i in range(n - pattern_len * 2 + 1):
            pattern = password[i:i+pattern_len]
            # Look for the same pattern repeating
            j = i + pattern_len
            if pattern == password[j:j+pattern_len]:
                return True
                
    return False


def detect_sequential_pattern(password: str, min_length: int = 3) -> bool:
    """
    Detect if password contains sequential patterns like '1234', 'abcd', etc.
    
    Args:
        password: The password to check
        min_length: Minimum length of pattern to detect
        
    Returns:
        bool: True if sequential pattern is detected
    """
    # Common sequences
    sequences = {
        'latin': 'abcdefghijklmnopqrstuvwxyz',
        'numbers': '0123456789',
        'devanagari': 'अआइईउऊएऐओऔकखगघङचछजझञटठडढणतथदधनपफबभमयरलवशषसह',
        'greek': 'αβγδεζηθικλμνξοπρστυφχψω',
        'chinese_pinyin': 'āáǎàēéěèīíǐìōóǒòūúǔùǖǘǚǜ'
    }
    
    # Check against each sequence
    for seq_name, sequence in sequences.items():
        # Forward sequence
        for i in range(len(sequence) - min_length + 1):
            pattern = sequence[i:i+min_length]
            if pattern.lower() in password.lower():
                return True
                
        # Reverse sequence
        rev_sequence = sequence[::-1]
        for i in range(len(rev_sequence) - min_length + 1):
            pattern = rev_sequence[i:i+min_length]
            if pattern.lower() in password.lower():
                return True
                
    return False


def identify_script(password: str) -> Dict[str, float]:
    """
    Identify which scripts/writing systems are used in the password
    
    Args:
        password: The password to analyze
        
    Returns:
        Dict[str, float]: A dictionary mapping script names to their percentage in the password
    """
    script_counts = {}
    total_chars = 0
    
    for char in password:
        if not char.isalpha():
            continue
            
        total_chars += 1
        script_name = unicodedata.name(char).split()[0]
        
        # Map some Unicode block names to more friendly names
        if script_name == "LATIN":
            script_name = "Latin (English/European)"
        elif script_name == "DEVANAGARI":
            script_name = "Devanagari (Hindi/Marathi)"
        elif script_name == "GREEK":
            script_name = "Greek"
        elif script_name in ("CJK", "HIRAGANA", "KATAKANA"):
            script_name = "Chinese/Japanese/Korean"
        elif script_name == "CYRILLIC":
            script_name = "Cyrillic (Russian)"
        elif script_name == "ARABIC":
            script_name = "Arabic"
        
        script_counts[script_name] = script_counts.get(script_name, 0) + 1
    
    # Convert counts to percentages
    if total_chars > 0:
        script_percentages = {script: count / total_chars * 100 for script, count in script_counts.items()}
    else:
        script_percentages = {}
    
    return script_percentages


def check_advanced_patterns(password: str) -> Dict[str, bool]:
    """
    Check for various advanced patterns in the password
    
    Args:
        password: The password to check
        
    Returns:
        Dict[str, bool]: Dictionary of pattern types and whether they were detected
    """
    patterns = {
        "keyboard_pattern": detect_keyboard_pattern(password),
        "repetitive_pattern": detect_repetitive_pattern(password),
        "sequential_pattern": detect_sequential_pattern(password),
        "scripts": identify_script(password)
    }
    
    return patterns


def calculate_pattern_complexity(patterns: Dict) -> float:
    """
    Calculate a pattern complexity score between 0-1
    
    Args:
        patterns: Dictionary containing pattern detection results
        
    Returns:
        float: Pattern complexity score (0-1)
    """
    # Start with full score
    score = 1.0
    
    # Penalize for different pattern types
    if patterns.get('keyboard_pattern', False):
        score -= 0.3
        
    if patterns.get('repetitive_pattern', False):
        score -= 0.3
        
    if patterns.get('sequential_pattern', False):
        score -= 0.25
    
    # Ensure score is between 0 and 1
    return max(0.0, min(1.0, score))


# Example usage
if __name__ == "__main__":
    test_passwords = [
        "password123",  # English with sequential numbers
        "qwerty",       # Keyboard pattern
        "abcabc",       # Repetitive pattern
        "हिन्दी123",     # Hindi mixed with numbers
        "γεια123",      # Greek mixed with numbers
        "密码123",       # Chinese mixed with numbers
        "P@s5w0rd!",    # Complex password with symbols
        "मराठी2023",     # Marathi with year
    ]
    
    print("Password Pattern Analysis:")
    print("-" * 70)
    for pwd in test_passwords:
        patterns = check_advanced_patterns(pwd)
        script_info = ", ".join([f"{s}: {p:.1f}%" for s, p in patterns['scripts'].items()])
        print(f"Password: {pwd}")
        print(f"  Keyboard Pattern: {patterns['keyboard_pattern']}")
        print(f"  Repetitive Pattern: {patterns['repetitive_pattern']}")
        print(f"  Sequential Pattern: {patterns['sequential_pattern']}")
        print(f"  Scripts Used: {script_info}")
        print(f"  Pattern Complexity: {calculate_pattern_complexity(patterns):.2f}")
        print("-" * 70) 