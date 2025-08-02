"""Enhanced demo program showcasing pattern detection and security tips."""

import sys
import os

# Add the project root to the Python path to fix import issues
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.interface.config import CustomData
from src.pipe.pipeline import Pipeline
from src.utils.feature_extraction import PatternTransform
from src.api.components import generate_password_tips, calculate_security_score


def analyze_password(password):
    """Analyze a password and print detailed information."""
    # Set up data handling
    pipeline = Pipeline()
    custom_data = CustomData()
    
    # Convert to dataframe and predict strength
    password_df = custom_data.data2df(password)
    strength = pipeline.predict(password_df)
    value = custom_data.array2data(strength)
    
    # Check for patterns
    pattern_checker = PatternTransform()
    has_pattern = bool(pattern_checker._patternTransform(password))
    
    # Get password tips
    tips = generate_password_tips(password, value)
    
    # Calculate security score
    score = calculate_security_score(value)
    
    # Print results
    print("\n═════════════════════════════════════════════")
    print(f"  PASSWORD ANALYSIS: '{password}'")
    print("═════════════════════════════════════════════")
    print(f"• Length: {len(password)} characters")
    print(f"• Strength Score: {value:.2f} (0-1 scale)")
    print(f"• Security Grade: {score}")
    print(f"• Contains Patterns: {'Yes' if has_pattern else 'No'}")
    
    print("\n📋 SECURITY RECOMMENDATIONS:")
    for i, tip in enumerate(tips, 1):
        print(f"  {i}. {tip}")
    print("═════════════════════════════════════════════\n")


def main():
    """Main function for the enhanced demo program."""
    print("\n🔒 ENHANCED PASSWORD ANALYZER 🔒")
    print("This tool analyzes passwords and provides security recommendations.")
    
    while True:
        print("\nOptions:")
        print("1. Analyze a password")
        print("2. Test sample passwords")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            password = input("\nEnter a password to analyze: ")
            analyze_password(password)
        
        elif choice == "2":
            # Test some sample passwords with different characteristics
            sample_passwords = [
                "password123",  # Common weak password
                "P@ssw0rd!",    # Medium strength with mixed characters
                "2June2023",    # Date pattern
                "qwerty123",    # Keyboard pattern
                "aB3!kD8@pL7#", # Strong password
            ]
            
            print("\n🔍 TESTING SAMPLE PASSWORDS")
            for password in sample_passwords:
                analyze_password(password)
        
        elif choice == "3":
            print("\nThank you for using the Enhanced Password Analyzer. Goodbye!")
            break
        
        else:
            print("\n❌ Invalid choice. Please try again.")


if __name__ == "__main__":
    main() 