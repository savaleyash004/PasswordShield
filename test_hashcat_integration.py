#!/usr/bin/env python3
"""
Test script for Hashcat integration in PassShield.

This script tests the Hashcat benchmarking and password crack time estimation
functionality that has been integrated into the PassShield model.
"""

import json
import time
from src.api.utils import (
    run_hashcat_benchmark,
    get_hash_rate,
    entropy_to_crack_time,
    calc_entropy,
    display_time,
    HASHCAT_MODES
)

def test_benchmark():
    """Test the Hashcat benchmark functionality."""
    print("Running Hashcat benchmark test...")
    
    # Try to run a benchmark for MD5 only (mode 0) for faster testing
    print("Attempting to run a Hashcat benchmark for MD5 (this should be quick)...")
    benchmark_results = run_hashcat_benchmark(0)  # MD5 mode
    
    if not benchmark_results:
        print("Hashcat benchmark failed or Hashcat is not installed.")
        print("Please make sure Hashcat is installed and available in your PATH.")
        print("If you don't have Hashcat installed, you can install it from:")
        print("  https://hashcat.net/hashcat/")
        return False
    
    print(f"Hashcat benchmark completed successfully with {len(benchmark_results)} hash types.")
    print("Sample of benchmark results:")
    
    # Print a sample of the results
    for hash_id, speed in list(benchmark_results.items())[:5]:
        hash_name = next((name for name, mode_id in HASHCAT_MODES.items() if mode_id == hash_id), f"Unknown ({hash_id})")
        print(f"  {hash_name}: {speed:,} hashes/second")
    
    return True

def test_password_crack_time():
    """Test password crack time estimation with different hash types."""
    print("\nTesting password crack time estimation...")
    
    test_passwords = [
        "password123",           # Very weak
        "P@ssw0rd!2023",         # Medium
        "nK8$p2%L9@zQ*7xG",      # Strong
        "kF5&rT9#pL2@qW7$mN3!x"   # Very strong
    ]
    
    hash_types = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'ntlm', 'argon2id', 'scrypt']
    
    print(f"{'Password':<25} {'Entropy (bits)':<15} {'Hash Type':<10} {'Crack Time'}")
    print("-" * 70)
    
    for password in test_passwords:
        entropy = calc_entropy(password)
        
        for hash_type in hash_types:
            crack_time_sec = entropy_to_crack_time(entropy, hash_type)
            crack_time_display = display_time(crack_time_sec)
            
            print(f"{password[:23]:<25} {entropy:<15.2f} {hash_type:<10} {crack_time_display}")
        
        print("-" * 70)
    
    return True

def test_cached_results():
    """Test that benchmark results are cached properly."""
    print("\nTesting benchmark caching functionality...")
    
    # First call should run the benchmark
    start = time.time()
    print("First call to get_hash_rate()...")
    rate1 = get_hash_rate('sha256')
    duration1 = time.time() - start
    
    print(f"SHA-256 hash rate: {rate1:,} hashes/second (took {duration1:.2f} seconds)")
    
    # Second call should use the cached results
    start = time.time()
    print("Second call to get_hash_rate() should use cached results...")
    rate2 = get_hash_rate('sha256')
    duration2 = time.time() - start
    
    print(f"SHA-256 hash rate: {rate2:,} hashes/second (took {duration2:.2f} seconds)")
    
    if duration2 < duration1:
        print("Caching is working correctly: second call was faster than the first.")
        return True
    else:
        print("Warning: Caching might not be working correctly.")
        return False

def main():
    """Run all the tests."""
    print("=" * 80)
    print("PassShield Hashcat Integration Test")
    print("=" * 80)
    
    benchmark_ok = test_benchmark()
    if benchmark_ok:
        crack_time_ok = test_password_crack_time()
        cache_ok = test_cached_results()
        
        if crack_time_ok and cache_ok:
            print("\nAll tests completed successfully!")
    
    print("\nNote: If Hashcat is not available, the system will fall back to the default hash rate.")
    print("      To get accurate results, please install Hashcat from https://hashcat.net/hashcat/")
    print("=" * 80)

if __name__ == "__main__":
    main() 