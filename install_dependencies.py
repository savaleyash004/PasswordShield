#!/usr/bin/env python
"""
Dependency installation script for PassShield.
This script automates the installation of required packages.
"""

import subprocess
import sys
import time
import os

def print_step(step, description):
    """Print a step in the installation process."""
    print(f"\n[{step}] {description}")
    time.sleep(0.5)

def run_command(command, error_message=None):
    """Run a command with error handling."""
    try:
        print(f"Running: {' '.join(command)}")
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        if result.stdout.strip():
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        if error_message:
            print(f"Error: {error_message}")
        print(f"Command failed: {' '.join(command)}")
        print(f"Error output: {e.stderr}")
        return False

def install_base_packages():
    """Install the base packages needed for PassShield."""
    print_step(1, "Installing base packages")
    
    packages = [
        "colorlog==6.7.0",
        "fastapi==0.100.0",
        "joblib==1.2.0",
        "numpy==1.22.4",
        "opendatasets==0.1.22",
        "pandas==1.5.3",
        "password-strength==0.0.3.post2",
        "pydantic==1.10.2",
        "pymongo==4.4.0",
        "python-dotenv==1.0.0",
        "scikit-learn==1.1.3",
        "uvicorn==0.23.0"
    ]
    
    return run_command(
        [sys.executable, "-m", "pip", "install"] + packages,
        "Failed to install base packages"
    )

def install_visualization_packages():
    """Install visualization packages."""
    print_step(2, "Installing visualization packages")
    
    # These are needed for notebooks but are not critical for API operation
    packages = [
        "plotly",
        "matplotlib",
        "seaborn",
        "ipywidgets"
    ]
    
    return run_command(
        [sys.executable, "-m", "pip", "install"] + packages,
        "Failed to install visualization packages (API will still work)"
    )

def install_advanced_ml_packages():
    """Install advanced machine learning packages."""
    print_step(3, "Installing advanced ML packages (may take some time)")
    
    # Try to install packages one by one as they might be more complex
    success = True
    
    # Install XGBoost
    if not run_command(
        [sys.executable, "-m", "pip", "install", "xgboost"],
        "Failed to install XGBoost (will use simpler models)"
    ):
        success = False
    
    # Install LightGBM (can be complex on some systems)
    if not run_command(
        [sys.executable, "-m", "pip", "install", "lightgbm"],
        "Failed to install LightGBM (will use simpler models)"
    ):
        success = False
        
    # Install CatBoost (can be large)
    if not run_command(
        [sys.executable, "-m", "pip", "install", "catboost"],
        "Failed to install CatBoost (will use simpler models)"
    ):
        success = False
        
    return success

def install_own_package():
    """Install the PassShield package itself."""
    print_step(4, "Installing PassShield package")
    
    return run_command(
        [sys.executable, "-m", "pip", "install", "-e", "."],
        "Failed to install PassShield package locally"
    )

def main():
    """Main installation function."""
    print("PassShield Dependencies Installation")
    print("=======================================")
    print("This script will install all required dependencies for PassShield.")
    print("It may take several minutes to complete.")
    
    # Install each group of dependencies
    base_success = install_base_packages()
    viz_success = install_visualization_packages()
    ml_success = install_advanced_ml_packages()
    package_success = install_own_package()
    
    # Print summary
    print("\n=======================================")
    print("Installation Summary:")
    print(f"- Base packages: {'✅ Success' if base_success else '❌ Failed'}")
    print(f"- Visualization packages: {'✅ Success' if viz_success else '❌ Failed (not critical)'}")
    print(f"- Advanced ML packages: {'✅ Success' if ml_success else '⚠️ Partial (will use simpler models)'}")
    print(f"- PassShield package: {'✅ Success' if package_success else '❌ Failed'}")
    
    if base_success:
        print("\nBasic functionality is available!")
        if not ml_success:
            print("Note: Advanced ML models are not available; the system will use simpler models.")
        if not viz_success:
            print("Note: Visualization packages are not available; notebooks may not work correctly.")
    else:
        print("\n❌ Critical packages failed to install. The system may not work correctly.")
    
    print("\nFor any issues, please check the error messages above.")

if __name__ == "__main__":
    main() 