import pandas as pd
import regex as re

# Function to check for sensitive information in a given text
def check_sensitive_info(text):
    # Define regex patterns for credit card numbers, social security numbers, names, health information, etc.
    credit_card_pattern = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
    ssn_pattern = re.compile(r'\b(?:\d[ -]*?){9}\b')
    name_pattern = re.compile(r'\b[A-Za-z]+\b')
    health_info_pattern = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')  # Example pattern for SSN

    # Check for matches
    has_credit_card = bool(credit_card_pattern.search(text))
    has_ssn = bool(ssn_pattern.search(text))
    has_name = bool(name_pattern.search(text))
    has_health_info = bool(health_info_pattern.search(text))

    return has_credit_card, has_ssn, has_name, has_health_info

# Read CSV file into a pandas DataFrame
df = pd.read_csv('your_data.csv')

# Iterate over rows and check for sensitive information
for index, row in df.iterrows():
    text_data = str(row['your_column'])  # Replace 'your_column' with the actual column name in your CSV

    credit_card, ssn, name, health_info = check_sensitive_info(text_data)

    # Now you can make decisions based on the sensitivity of the data
    if credit_card or ssn or name or health_info:
        # Handle the data based on its sensitivity (e.g., encryption, logging, etc.)
        print(f"Sensitive information found in row {index + 1}")

# You can do similar processing for TXT files by reading the file line by line or as a whole
