import requests
import csv
import time
import os

# CONFIGURE THIS:
API_URL = "http://127.0.0.1:8001/predict"  # Changed port to 8000 which is the default FastAPI port
HEADERS = {
    "Content-Type": "application/json",
    # "Authorization": "Bearer YOUR_TOKEN",  # if needed
}
METHOD = "POST"  # or "GET"
INPUT_FILE = "Validation_Dataset_1_final.csv"  # your passwords input
OUTPUT_FILE = "responses.csv"  # where to save output
DELAY_BETWEEN_REQUESTS = 0.2  # seconds

# Make sure input file exists
if not os.path.exists(INPUT_FILE):
    print(f"Input file {INPUT_FILE} not found. Looking in current directory: {os.getcwd()}")
    print(f"Files in current directory: {os.listdir('.')}")
    exit(1)

# Read passwords from CSV
passwords = []
try:
    with open(INPUT_FILE, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            passwords.append(row['password'])
    print(f"Successfully loaded {len(passwords)} passwords from {INPUT_FILE}")
except Exception as e:
    print(f"Error reading input file: {e}")
    exit(1)

# Write output CSV
try:
    with open(OUTPUT_FILE, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['password', 'status_code', 'class_strength', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        success_count = 0
        error_count = 0

        for password in passwords:
            # Prepare payload
            payload = {
                "password": password
                # add other fields if needed
            }

            # Send request
            try:
                if METHOD == "POST":
                    response = requests.post(API_URL, json=payload, headers=HEADERS, timeout=5)
                else:
                    response = requests.get(API_URL, params=payload, headers=HEADERS, timeout=5)

                print(f"Password: {password} | Status: {response.status_code}")

                try:
                    # Parse the JSON and extract class_strength
                    data = response.json()
                    class_strength = data.get('class_strength', 'N/A')
                    success_count += 1
                except Exception as parse_error:
                    class_strength = 'N/A'
                    error_message = f"ParseError: {parse_error}"
                    error_count += 1
                    print(f"  Error parsing response: {error_message}")

                # Write to output
                writer.writerow({
                    'password': password,
                    'status_code': response.status_code,
                    'class_strength': class_strength,
                    'error': '' if response.status_code == 200 else f"HTTP {response.status_code}"
                })

            except requests.exceptions.ConnectionError:
                error_message = "Connection error - Is the API server running?"
                print(f"  {error_message}")
                writer.writerow({
                    'password': password,
                    'status_code': 'ERROR',
                    'class_strength': 'N/A',
                    'error': error_message
                })
                error_count += 1
            except Exception as e:
                error_message = str(e)
                print(f"  Error with password {password}: {error_message}")
                writer.writerow({
                    'password': password,
                    'status_code': 'ERROR',
                    'class_strength': 'N/A',
                    'error': error_message
                })
                error_count += 1

            time.sleep(DELAY_BETWEEN_REQUESTS)  # avoid rate limits
            
        print(f"\nResults: {success_count} successful, {error_count} errors")
        print(f"Response data saved to {os.path.abspath(OUTPUT_FILE)}")
except Exception as e:
    print(f"Error writing to output file: {e}")
    exit(1)