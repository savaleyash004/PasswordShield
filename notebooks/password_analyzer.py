"""
PassShield Password Analyzer

This module integrates all features of the PassShield password analysis system,
including strength prediction, script detection, pattern analysis, breach checking,
hash crack time estimation, security score, and password improvement tips.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List

# Import all our modules
from pattern_detection import (
    check_advanced_patterns, 
    identify_script
)
from breach_detection import (
    get_breach_recommendations,
    format_breach_summary
)
from hash_crack_times import (
    estimate_crack_time,
    format_crack_time_summary
)
from security_score import (
    get_security_summary,
    format_security_summary
)

class PasswordAnalyzer:
    """
    Comprehensive password analyzer that combines all PassShield features
    """
    
    def __init__(self):
        """Initialize the PasswordAnalyzer"""
        pass
        
    def analyze_password(self, password: str) -> Dict:
        """
        Run comprehensive analysis on a password
        
        Args:
            password: The password to analyze
            
        Returns:
            Dict: Complete analysis results
        """
        # Get results from all analysis modules
        patterns = check_advanced_patterns(password)
        scripts = identify_script(password)
        breach_info = get_breach_recommendations(password)
        crack_time = estimate_crack_time(password)
        security = get_security_summary(password)
        
        # Combine all results into a single structure
        return {
            'password': password,
            'length': len(password),
            'security_score': security['score'],
            'security_rating': security['rating'],
            'security_grade': security['grade'],
            'risk_level': security['risk_level'],
            'has_pattern': patterns['keyboard_pattern'] or patterns['repetitive_pattern'] or patterns['sequential_pattern'],
            'pattern_details': {
                'keyboard_pattern': patterns['keyboard_pattern'],
                'repetitive_pattern': patterns['repetitive_pattern'],
                'sequential_pattern': patterns['sequential_pattern']
            },
            'scripts_used': scripts,
            'breach_info': breach_info,
            'crack_times': crack_time['crack_times'],
            'complexity': crack_time['complexity'],
            'improvement_tips': security['improvement_tips']
        }
        
    def format_analysis(self, result: Dict) -> str:
        """
        Create a human-readable summary of password analysis
        
        Args:
            result: The analysis result dictionary
            
        Returns:
            str: Formatted analysis report
        """
        output = [
            f"Analysis for: {result['password']}",
            f"Length: {result['length']} characters",
            f"Security Score: {result['security_score']}/100 ({result['security_rating']}, Grade: {result['security_grade']})",
            f"Risk Level: {result['risk_level']}",
            ""
        ]
        
        # Add script information
        if result['scripts_used']:
            scripts_str = ", ".join([f"{script}: {percent:.1f}%" for script, percent in result['scripts_used'].items()])
            output.append(f"Scripts Used: {scripts_str}")
            output.append("")
        
        # Add pattern information
        pattern_details = result['pattern_details']
        if result['has_pattern']:
            output.append("Patterns Detected:")
            if pattern_details['keyboard_pattern']:
                output.append("  • Keyboard pattern detected (e.g., 'qwerty', 'asdfgh')")
            if pattern_details['sequential_pattern']:
                output.append("  • Sequential pattern detected (e.g., '12345', 'abcde')")
            if pattern_details['repetitive_pattern']:
                output.append("  • Repetitive pattern detected (e.g., 'abcabc')")
            output.append("")
        
        # Add breach information (simplified)
        if result['breach_info']['found_in_breach']:
            output.append(f"⚠️ Password found in {result['breach_info']['breach_count']} known data breaches!")
            output.append("")
        
        # Add crack time information (simplified)
        gpu_times = result['crack_times']['gpu']
        output.append("Estimated time to crack (using high-end GPU):")
        output.append(f"  • Dictionary attack: {gpu_times['dictionary']['human_readable']}")
        output.append(f"  • Brute force attack: {gpu_times['brute_force']['human_readable']}")
        output.append("")
        
        # Add improvement tips
        output.append("Improvement Tips:")
        for i, tip in enumerate(result['improvement_tips'], 1):
            output.append(f"  {i}. {tip}")
        
        return "\n".join(output)
    
    def analyze_and_print(self, password: str) -> None:
        """
        Analyze a password and print formatted results
        
        Args:
            password: The password to analyze
        """
        result = self.analyze_password(password)
        print(self.format_analysis(result))
    
    def analyze_batch(self, passwords: List[str]) -> pd.DataFrame:
        """
        Analyze a batch of passwords and return a DataFrame with results
        
        Args:
            passwords: List of passwords to analyze
            
        Returns:
            pd.DataFrame: DataFrame with analysis results
        """
        results = []
        for pwd in passwords:
            analysis = self.analyze_password(pwd)
            
            # Extract key metrics for DataFrame
            row = {
                'password': analysis['password'],
                'length': analysis['length'],
                'security_score': analysis['security_score'],
                'security_rating': analysis['security_rating'],
                'risk_level': analysis['risk_level'],
                'has_pattern': analysis['has_pattern'],
                'found_in_breach': analysis['breach_info']['found_in_breach'],
                'dictionary_crack_time': analysis['crack_times']['gpu']['dictionary']['human_readable'],
                'brute_force_crack_time': analysis['crack_times']['gpu']['brute_force']['human_readable'],
                'scripts': ','.join(list(analysis['scripts_used'].keys())),
                'tips_count': len(analysis['improvement_tips'])
            }
            results.append(row)
            
        return pd.DataFrame(results)
    
    def visualize_batch_results(self, df: pd.DataFrame) -> None:
        """
        Create visualizations for batch analysis results
        
        Args:
            df: DataFrame with batch analysis results
        """
        # Set up the figure
        plt.figure(figsize=(18, 10))
        
        # 1. Security score distribution
        plt.subplot(2, 2, 1)
        sns.histplot(df['security_score'], bins=10, kde=True)
        plt.title('Security Score Distribution')
        plt.xlabel('Security Score')
        plt.ylabel('Count')
        
        # 2. Security ratings
        plt.subplot(2, 2, 2)
        rating_counts = df['security_rating'].value_counts().sort_index()
        sns.barplot(x=rating_counts.index, y=rating_counts.values)
        plt.title('Security Rating Distribution')
        plt.xlabel('Rating')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        
        # 3. Pattern and breach percentages
        plt.subplot(2, 2, 3)
        pattern_pct = df['has_pattern'].mean() * 100
        breach_pct = df['found_in_breach'].mean() * 100
        sns.barplot(x=['Has Pattern', 'Found in Breach'], 
                   y=[pattern_pct, breach_pct])
        plt.title('Pattern and Breach Percentages')
        plt.xlabel('Issue Type')
        plt.ylabel('Percentage')
        
        # 4. Password length vs. security score
        plt.subplot(2, 2, 4)
        sns.scatterplot(data=df, x='length', y='security_score', 
                       hue='risk_level', palette='viridis')
        plt.title('Password Length vs. Security Score')
        plt.xlabel('Password Length')
        plt.ylabel('Security Score')
        
        plt.tight_layout()
        plt.show()

# Example usage
if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    
    print("Single Password Analysis:")
    print("-" * 70)
    analyzer.analyze_and_print("P@ssw0rd123")
    print("-" * 70)
    
    # Batch analysis example
    test_passwords = [
        "password123",
        "qwerty",
        "P@s5w0rd!2023",
        "हिन्दी123",
        "γεια123",
        "मराठी2023",
        "SuperSecureP@ssw0rd!",
        "Tröödlå123$Væry&Str0ng",
        "admin123",
        "letmein",
        "welcome1",
        "monkey123",
        "123456789",
        "abcdef",
        "football",
        "iloveyou",
        "dragon",
        "sunshine",
        "master",
        "hello123",
    ]
    
    print("\nBatch Analysis Results:")
    results_df = analyzer.analyze_batch(test_passwords)
    print(results_df[['password', 'security_score', 'security_rating', 'risk_level', 'has_pattern', 'found_in_breach']])
    
    # Uncomment to show visualizations
    # analyzer.visualize_batch_results(results_df) 