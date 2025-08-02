import csv
import requests
import json

# Define the Llama API endpoint and API key (replace with actual key)
LLAMA_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/llama-1.5-flash:generateContent"
API_KEY = "AIzaSyB9RS32rJ4qFzTrkCas7c-wD0jTZ8_-sjA"

# Function to call the Llama API and analyze the password
def analyze_password_for_pii(password):
    # Define the payload for the Llama API request
    payload = {
        "password": password,
        "temperature": 0.7,
        "max_length": 80
    }
    
    # Headers with the API key (replace with actual header format if needed)
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    # Send POST request to Llama API
    try:
        response = requests.post(LLAMA_API_URL, json=payload, headers=headers)
        response.raise_for_status()  # Check for request errors
        result = response.json()  # Parse the JSON response

        # Check if PII is detected in the response
        pii_detected = "matched" if result["containsPII"] else "mismatched"
        return pii_detected, result.get("detailedAnalysis", "")
    except requests.exceptions.RequestException as e:
        print(f"Error calling Llama API: {e}")
        return "error", str(e)

# Function to process the input CSV and generate the output CSV
def process_csv(input_file, output_file):
    # Open the input CSV file for reading
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        # Define the fieldnames for the output CSV file
        fieldnames = reader.fieldnames + ['PII Status', 'Detailed Analysis']

        # Open the output CSV file for writing
        with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            # Process each row in the input CSV file
            for row in reader:
                password = row.get("password", "")
                if password:
                    pii_status, analysis = analyze_password_for_pii(password)
                    row['PII Status'] = pii_status
                    row['Detailed Analysis'] = analysis
                else:
                    row['PII Status'] = "missing password"
                    row['Detailed Analysis'] = "No password provided"

                # Write the updated row to the output CSV file
                writer.writerow(row)

    print(f"Output saved to {output_file}")

# Main execution block
if __name__ == "__main__":
    input_csv = "input.csv"  # Input CSV file with passwords
    output_csv = "output.csv"  # Output CSV file to store results

    # Process the input file and generate the output
    process_csv(input_csv, output_csv)
