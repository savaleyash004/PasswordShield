#!/usr/bin/env python3
"""
Test script for the hashcat wrapper
"""

import sys
import subprocess
import time

def main():
    print("Testing hashcat wrapper...")
    
    # Test version check
    print("\nTesting version check:")
    start = time.time()
    result = subprocess.run(
        ["python", "hashcat_wrapper.py", "--version"],
        capture_output=True,
        text=True
    )
    print(f"Version output: {result.stdout.strip()}")
    print(f"Time taken: {time.time() - start:.2f} seconds")
    
    # Test MD5 benchmark
    print("\nTesting MD5 benchmark (should be quick):")
    start = time.time()
    result = subprocess.run(
        ["python", "hashcat_wrapper.py", "-b", "-m", "0", "--machine-readable"],
        capture_output=False,
        text=True
    )
    print(f"Benchmark completed with exit code: {result.returncode}")
    print(f"Time taken: {time.time() - start:.2f} seconds")
    
    print("\nWrapper test completed!")

if __name__ == "__main__":
    main() 