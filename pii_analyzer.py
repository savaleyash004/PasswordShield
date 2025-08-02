import csv
import requests
import json
import os
import time
import random
from tqdm import tqdm  # For progress bar

# Rate limit settings
MAX_RETRIES = 5
INITIAL_RETRY_DELAY = 2  # seconds
MAX_RETRY_DELAY = 60  # seconds
QUOTA_EXCEEDED_COUNT_THRESHOLD = 3  # Switch to fallback after this many quota errors

# Global counter for quota exceeded errors
quota_exceeded_count = 0

# Fallback PII detection function using basic regex patterns and rules
def fallback_pii_detection(password):
    # Define some simple patterns for common PII
    contains_pii = False
    reason = "No PII detected"
    
    # Check for potential dates (MM/DD/YYYY, MM-DD-YYYY, MMDDYYYY, etc.)
    date_patterns = [
        r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',  # MM/DD/YY or MM-DD-YY
        r'\b\d{4}\d{2}\d{2}\b',  # YYYYMMDD
        r'\b\d{2}\d{2}\d{4}\b',  # MMDDYYYY
    ]
    
    # Check for potential phone numbers
    phone_patterns = [
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # 123-456-7890
        r'\b\(\d{3}\)\s*\d{3}[-.\s]?\d{4}\b',  # (123) 456-7890
    ]
    
    # Words that might indicate names or personal information
    personal_indicators = ["name", "birth", "street", "address", "pet", "child", "wife", "husband"]
    
    # Check for common name patterns - names with 4+ chars that are capitalized
    name_pattern = r'\b[A-Z][a-z]{3,}\b'
    
    # Check for email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Check if password contains digits that look like years (19XX or 20XX)
    year_pattern = r'\b(19\d{2}|20\d{2})\b'
    
    import re
    
    # Check all patterns
    for pattern in date_patterns:
        if re.search(pattern, password):
            contains_pii = True
            reason = "Password may contain a date (birthday, anniversary)"
            break
    
    if not contains_pii:
        for pattern in phone_patterns:
            if re.search(pattern, password):
                contains_pii = True
                reason = "Password may contain a phone number"
                break
    
    if not contains_pii and re.search(email_pattern, password):
        contains_pii = True
        reason = "Password may contain an email address"
    
    if not contains_pii and re.search(name_pattern, password):
        contains_pii = True
        reason = "Password may contain a name"
    
    if not contains_pii and re.search(year_pattern, password):
        contains_pii = True
        reason = "Password may contain a year (possibly birth year)"
    
    if not contains_pii:
        for indicator in personal_indicators:
            if indicator.lower() in password.lower():
                contains_pii = True
                reason = f"Password contains the word '{indicator}' which may indicate personal information"
                break
    
    # Length-based heuristic: very long passwords (16+ chars) that aren't random are likely to contain personal info
    if not contains_pii and len(password) > 16:
        # Check if password appears to be non-random (fewer than 40% special chars and numbers)
        special_and_nums = sum(1 for char in password if not char.isalpha())
        if special_and_nums / len(password) < 0.4:
            contains_pii = True
            reason = "Long password with mostly letters may contain personal information like phrases or names"
    
    return "matched" if contains_pii else "mismatched", reason

# Function to call the Llama API with retry logic
def analyze_password_with_llama(password):
    global quota_exceeded_count
    
    # If we've exceeded the quota threshold, use fallback method
    if quota_exceeded_count >= QUOTA_EXCEEDED_COUNT_THRESHOLD:
        print("Using fallback PII detection due to quota limitations")
        return fallback_pii_detection(password)
    
    # Create the prompt for PII detection
    prompt = f"""You are an AI assistant specializing in password security analysis. 
    You need to examine this password for any personally identifiable information (PII): "{password}"
    
    Analyze if this password contains any of the following PII categories:
    - Full names or parts of names
    - Contact information (emails, phone numbers)
    - Locations, addresses, cities
    - Dates (birthdays, anniversaries)
    - Government or personal ID numbers
    - Financial information
    - Vehicle information
    - Pet names or other personal identifiers
    
    Respond with ONLY a simple JSON object: {{"containsPII": true/false, "reason": "brief explanation"}}
    """
    
    retry_count = 0
    retry_delay = INITIAL_RETRY_DELAY
    
    while retry_count < MAX_RETRIES:
        try:
            response = requests.post(
                f"{LLAMA_API_URL}?key={API_KEY}",
                headers={
                    "Content-Type": "application/json"
                },
                json={
                    "contents": [{
                        "parts": [{
                            "text": prompt
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 200
                    }
                }
            )
            
            # If we hit a rate limit (429)
            if response.status_code == 429:
                quota_exceeded_count += 1
                print(f"Rate limit hit ({quota_exceeded_count}/{QUOTA_EXCEEDED_COUNT_THRESHOLD})")
                
                # If we've hit the threshold, switch to fallback
                if quota_exceeded_count >= QUOTA_EXCEEDED_COUNT_THRESHOLD:
                    print("Quota exceeded threshold - switching to fallback method")
                    return fallback_pii_detection(password)
                
                # Otherwise exponential backoff with jitter
                jitter = random.uniform(0, 0.1 * retry_delay)
                sleep_time = min(retry_delay + jitter, MAX_RETRY_DELAY)
                print(f"Retrying in {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
                retry_delay *= 2  # Exponential backoff
                retry_count += 1
                continue
            
            # Other API errors
            elif response.status_code != 200:
                print(f"Error: {response.status_code}, {response.text}")
                retry_count += 1
                time.sleep(retry_delay)
                retry_delay *= 2
                continue
            
            # Parse the response
            result = response.json()
            text_response = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            
            # Extract JSON from the response
            try:
                # Look for JSON object in the response
                json_match = text_response.strip().replace("```json", "").replace("```", "")
                analysis = json.loads(json_match)
                
                # Return matched/mismatched based on containsPII
                if analysis.get("containsPII", False):
                    return "matched", analysis.get("reason", "PII detected")
                else:
                    return "mismatched", analysis.get("reason", "No PII detected")
                    
            except json.JSONDecodeError as e:
                # If we can't parse JSON, try to determine from the text
                if "true" in text_response.lower() and "pii" in text_response.lower():
                    return "matched", "PII likely detected (parsing error)"
                else:
                    return "mismatched", "No PII likely (parsing error)"
        
        except Exception as e:
            print(f"Error analyzing password: {e}")
            retry_count += 1
            time.sleep(retry_delay)
            retry_delay *= 2
            continue
    
    # If we've exhausted all retries, use the fallback
    print(f"Exhausted all retries for API, using fallback method")
    return fallback_pii_detection(password)

# Function to process the dataset and generate output with PII analysis
def analyze_dataset(input_file, output_file, batch_size=5):
    try:
        # Check if input file exists
        if not os.path.exists(input_file):
            print(f"Input file not found: {input_file}")
            return False
            
        # Read the input CSV file
        with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            
            # Get all field names and add our result column
            fieldnames = reader.fieldnames + ['result', 'reason']
            
            # Create the output file
            with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Get total rows for progress bar
                infile.seek(0)  # Reset to beginning
                next(infile)  # Skip header
                total_rows = sum(1 for _ in infile)
                infile.seek(0)  # Reset again
                reader = csv.DictReader(infile)  # Recreate reader
                
                # Create a buffer to batch process passwords
                batch_counter = 0
                
                # Process each row with a progress bar
                for row in tqdm(reader, total=total_rows, desc="Analyzing passwords"):
                    # Get the password from gen_pass field
                    password = row.get("gen_pass", "")
                    
                    # Skip if no password
                    if not password:
                        row['result'] = "error"
                        row['reason'] = "No password in gen_pass field"
                    else:
                        # Analyze the password
                        result, reason = analyze_password_with_llama(password)
                        row['result'] = result
                        row['reason'] = reason
                    
                    # Write the row with the analysis result
                    writer.writerow(row)
                    
                    # Implement controlled pacing - sleep after each batch
                    batch_counter += 1
                    if batch_counter >= batch_size:
                        time.sleep(1)  # Pause for 1 second after each batch
                        batch_counter = 0
                    
        print(f"Analysis complete. Results saved to {output_file}")
        return True
        
    except Exception as e:
        print(f"Error processing dataset: {e}")
        return False

if __name__ == "__main__":
    # Input and output file paths
    input_file = "Validation_Dataset_2_final (1).csv"
    output_file = "output.csv"
    
    print(f"Starting PII analysis on {input_file}")
    analyze_dataset(input_file, output_file, batch_size=5)  # Process in small batches 