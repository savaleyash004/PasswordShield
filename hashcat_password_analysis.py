#!/usr/bin/env python3
"""
Standalone Password Analysis Script with Hashcat Integration

This script demonstrates how to use the Hashcat integration in PassShield
to analyze password strength and estimate crack times for different hash algorithms.
"""

import argparse
import json
import sys
from tabulate import tabulate

from src.api.utils import (
    run_hashcat_benchmark,
    get_hash_rate,
    entropy_to_crack_time,
    calc_entropy,
    display_time,
    calc_strength,
    calc_class_strength,
    HASHCAT_MODES
)

def analyze_password(password, hash_algorithms=None):
    """
    Analyze a password and estimate crack times for different hash algorithms.
    
    Args:
        password (str): The password to analyze
        hash_algorithms (list): List of hash algorithms to analyze (default: all supported)
        
    Returns:
        dict: Analysis results
    """
    if not hash_algorithms:
        hash_algorithms = list(HASHCAT_MODES.keys())
    
    # Calculate base metrics
    entropy = calc_entropy(password)
    strength = calc_strength(password)
    strength_class = calc_class_strength(strength)
    
    # Get crack times for each algorithm
    crack_times = {}
    for hash_type in hash_algorithms:
        if hash_type not in HASHCAT_MODES:
            print(f"Warning: Unknown hash type '{hash_type}', skipping.")
            continue
            
        # Get hash rate and calculate crack time
        try:
            hash_rate = get_hash_rate(hash_type)
            crack_time_sec = entropy_to_crack_time(entropy, hash_type)
            
            crack_times[hash_type] = {
                "hash_rate": hash_rate,
                "seconds": crack_time_sec,
                "display": display_time(crack_time_sec)
            }
        except Exception as e:
            print(f"Error analyzing with {hash_type}: {str(e)}")
    
    return {
        "password": password,
        "length": len(password),
        "entropy": entropy,
        "strength": strength,
        "strength_class": strength_class,
        "crack_times": crack_times
    }

def print_table_format(analysis):
    """Print password analysis in a tabular format."""
    print(f"\nPassword Analysis: '{analysis['password']}'")
    print(f"Length: {analysis['length']} characters")
    print(f"Entropy: {analysis['entropy']:.2f} bits")
    print(f"Strength: {analysis['strength']:.4f} ({analysis['strength_class']})")
    
    # Create a table of crack times
    table_data = []
    for hash_type, details in analysis['crack_times'].items():
        table_data.append([
            hash_type,
            f"{details['hash_rate']:,} H/s",
            details['display']
        ])
    
    print("\nEstimated crack times by hash algorithm:")
    print(tabulate(
        table_data,
        headers=["Hash Algorithm", "Hash Rate", "Time to Crack"],
        tablefmt="grid"
    ))

def print_json_format(analysis):
    """Print password analysis in JSON format."""
    print(json.dumps(analysis, indent=2))

def main():
    """Main function to run the password analysis script."""
    parser = argparse.ArgumentParser(description='Analyze password security with Hashcat integration')
    parser.add_argument('password', help='Password to analyze')
    parser.add_argument('--hash-types', nargs='+', help='Hash types to analyze (default: all supported)',
                        default=['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'ntlm', 'argon2id', 'scrypt'])
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()
    
    # Analyze the password
    analysis = analyze_password(args.password, args.hash_types)
    
    # Print results
    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print_table_format(analysis)

if __name__ == "__main__":
    main() 