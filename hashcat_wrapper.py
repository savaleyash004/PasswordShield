#!/usr/bin/env python3
"""
Hashcat Wrapper Script

This script ensures hashcat runs from its installation directory
so it can find the OpenCL files and other dependencies.
"""

import os
import sys
import subprocess

# Path to hashcat executable directory - adjust this to your installation path
HASHCAT_PATH = r"C:\HashCat\hashcat-6.2.6\hashcat-6.2.6"

def main():
    # Get arguments passed to the script
    args = sys.argv[1:]
    
    # Special handling for --version to make it faster
    if args and args[0] == "--version":
        return run_version_check()
    
    # Change to hashcat directory
    original_dir = os.getcwd()
    os.chdir(HASHCAT_PATH)
    
    try:
        # Run hashcat with the given arguments
        cmd = ["hashcat.exe"] + args
        print(f"Running hashcat from {HASHCAT_PATH}")
        print(f"Command: {' '.join(cmd)}")
        
        # Use real-time output for long-running commands
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Print output in real-time
        stdout_lines = []
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
            stdout_lines.append(line)
            sys.stdout.flush()
        
        # Wait for process to complete
        return_code = process.wait()
        
        # Get any remaining stderr
        stderr = process.stderr.read()
        if stderr:
            print("ERRORS:", file=sys.stderr)
            print(stderr, file=sys.stderr)
        
        return return_code
    finally:
        # Change back to original directory
        os.chdir(original_dir)

def run_version_check():
    """Run a quick version check without full subprocess setup."""
    original_dir = os.getcwd()
    os.chdir(HASHCAT_PATH)
    
    try:
        result = subprocess.run(
            ["hashcat.exe", "--version"],
            capture_output=True,
            text=True
        )
        print(result.stdout.strip())
        return result.returncode
    finally:
        os.chdir(original_dir)

if __name__ == "__main__":
    sys.exit(main()) 