import requests
import pandas as pd
import json
import os
from datetime import datetime, timedelta
import time
from colorama import init, Fore, Style
import logging
from openpyxl import load_workbook
from openpyxl.styles import Alignment
import socket
import whois
import tldextract

# Initialize colorama
init()

# Configure logging
logging.basicConfig(filename='domain_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load API keys from api_keys.json
with open('api_keys.json') as config_file:
    config = json.load(config_file)
api_keys = config['api_keys']
api_key = api_keys[0]  # Use the first API key

# Caching scores for apex and domain to avoid duplicate analysis
score_cache = {}
apex_score_cache = {}
last_request_time = 0
RATE_LIMIT_DELAY = 15  # seconds

# Helper function to rate-limit API requests
def rate_limited_request():
    global last_request_time
    elapsed = time.time() - last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)
    last_request_time = time.time()

# Function to check the domain without re-analysis
def check_domain(domain):
    if domain in score_cache:
        return score_cache[domain]
    rate_limited_request()
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'attributes' in data['data']:
            malicious_score = data['data']['attributes']['last_analysis_stats']['malicious']
            score_cache[domain] = malicious_score
            logging.info(f"Domain checked successfully: {domain}")
            print(Fore.GREEN + f"Domain checked successfully: {domain}" + Style.RESET_ALL)
            return malicious_score
        else:
            logging.warning(f"Missing expected keys in API response for domain: {domain}")
            print(Fore.YELLOW + f"Unexpected format in response for: {domain}" + Style.RESET_ALL)
            return None
    else:
        logging.error(f"Error checking domain: {domain}. Response: {response.content}")
        print(Fore.RED + f"Error checking domain: {domain}. Response: {response.content}" + Style.RESET_ALL)
        return None

# Function to request a re-analysis of the domain
def request_reanalysis_domain(domain):
    rate_limited_request()
    headers = {
        "x-apikey": api_key
    }
    response = requests.post(f"https://www.virustotal.com/api/v3/domains/{domain}/analyse", headers=headers)
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        logging.info(f"Re-analysis requested successfully: {domain}")
        print(Fore.GREEN + f"Re-analysis requested successfully: {domain}" + Style.RESET_ALL)
        return analysis_id
    else:
        logging.error(f"Error requesting re-analysis: {domain}. Response: {response.content}")
        print(Fore.RED + f"Error requesting re-analysis: {domain}. Response: {response.content}" + Style.RESET_ALL)
        return None

# Function to get the number of vendors that flagged the domain as malicious after re-analysis
def get_malicious_score_domain(analysis_id, domain):
    headers = {
        "x-apikey": api_key
    }
    while True:
        rate_limited_request()
        response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data['data']['attributes']['status']
            if status == 'completed':
                malicious_score = data['data']['attributes']['stats']['malicious']
                score_cache[domain] = malicious_score
                logging.info(f"Re-analysis completed successfully: {domain}")
                print(Fore.GREEN + f"Re-analysis completed successfully: {domain}" + Style.RESET_ALL)
                return malicious_score
            else:
                logging.info(f"Waiting for re-analysis to complete: {domain}")
                print(Fore.YELLOW + f"Waiting for re-analysis to complete: {domain}" + Style.RESET_ALL)
                time.sleep(15)
        else:
            logging.error(f"Error retrieving re-analysis results: {domain}. Response: {response.content}")
            print(Fore.RED + f"Error retrieving re-analysis results: {domain}. Response: {response.content}" + Style.RESET_ALL)
            return None

# Function to extract apex domain
def extract_apex_domain(domain):
    extracted = tldextract.extract(domain)
    apex = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else domain
    return apex

# Function to get the malicious score for domains with rate limiting and apex option
def get_malicious_score_with_rate_limit_domain(domain, option, index, total, return_apex=False):
    if option in ['1', '2']:
        score = check_or_reanalyse(domain, option)
    elif option == '3':
        apex = extract_apex_domain(domain)
        score_domain = check_or_reanalyse(domain, '1')

        # For apex domain, we now overwrite the cache with the latest result.
        # If the apex domain's result is available, we'll update the cache with the new score
        score_apex = None
        if apex in apex_score_cache:
            # Clear the previous apex score (reset the cache for the current scan)
            apex_score_cache[apex] = None

        score_apex = check_or_reanalyse(apex, '1')
        apex_score_cache[apex] = score_apex  # Store the result for the current scan only

        # Ensure that both scores are valid before comparing
        score = max(score_domain or 0, score_apex or 0)
        print(Fore.CYAN + f"Completed {index + 1}/{total}. {total - (index + 1)} left." + Style.RESET_ALL)
        
        if return_apex:
            return score_apex  # Return apex domain score if requested
    else:
        score = None
    time.sleep(15)
    return score

# Common logic for domain or re-analysis
def check_or_reanalyse(domain, mode):
    if mode == '1':
        return check_domain(domain)
    elif mode == '2':
        analysis_id = request_reanalysis_domain(domain)
        if analysis_id:
            return get_malicious_score_domain(analysis_id, domain)
    return None

# Function to resolve the IP address for a domain
def resolve_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        logging.info(f"IP resolved successfully: {domain} -> {ip_address}")
        print(Fore.GREEN + f"IP resolved successfully: {domain} -> {ip_address}" + Style.RESET_ALL)
        return ip_address
    except socket.error as e:
        logging.error(f"Error resolving IP for domain: {domain}. Error: {e}")
        print(Fore.RED + f"Error resolving IP for domain: {domain}. Error: {e}" + Style.RESET_ALL)
        return "IP Not Resolved"

# Function to get the domain creation date and age
def get_domain_creation_date_and_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        formatted_age = format_age(age)
        logging.info(f"Domain creation date and age retrieved successfully: {domain} -> {creation_date}, {formatted_age}")
        print(Fore.GREEN + f"Domain creation date and age retrieved successfully: {domain} -> {creation_date}, {formatted_age}" + Style.RESET_ALL)
        return creation_date, formatted_age
    except Exception as e:
        logging.error(f"Error retrieving domain creation date and age for domain: {domain}. Error: {e}")
        print(Fore.RED + f"Error retrieving domain creation date and age for domain: {domain}. Error: {e}" + Style.RESET_ALL)
        return "Creation Date Not Available", "Domain Age Not Available"

# Function to format the domain age dynamically
def format_age(age):
    if age >= 365:
        years = age // 365
        months = (age % 365) // 30
        if months > 0:
            return f"{years} yr {months} months"
        else:
            return f"{years} yr"
    elif age >= 30:
        months = age // 30
        return f"{months} months"
    else:
        return f"{age} days"

# Prompt user to select an option
print("Select an option:")
print("1. Check Domain")
print("2. Re-analyze Domain")
print("3. Check Both Domain and Apex Domain")
option = input("Enter the option number (1, 2, or 3): ")

# Load the input Excel file
input_file = 'Domain_input.xlsx'
df = pd.read_excel(input_file)

# Add new columns for the malicious score, IP address, and domain creation date and age with rate limiting
total_domains = len(df['Domain'])
df['Number Vendors Flagged as Malicious(Domain)'] = [
    get_malicious_score_with_rate_limit_domain(domain, option, index, total_domains)
    for index, domain in enumerate(df['Domain'])
]

df['Number Vendors Flagged as Malicious(Apex Domain)'] = [
    get_malicious_score_with_rate_limit_domain(domain, option, index, total_domains, return_apex=True)
    for index, domain in enumerate(df['Domain'])
]

df['IP Address'] = [resolve_ip(domain) for domain in df['Domain']]
df['Domain Creation Date'], df['Domain Age'] = zip(*[get_domain_creation_date_and_age(domain) for domain in df['Domain']])

# Create the output Excel file with categorized sheets
current_datetime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
output_dir = 'Domain_response'

# Check if output folder exists, otherwise create it
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Filter and save to separate sheets based on malicious score
clean_df = df[df['Number Vendors Flagged as Malicious(Domain)'] == 0]
suspicious_df = df[df['Number Vendors Flagged as Malicious(Domain)'] == 1]
malicious_df = df[df['Number Vendors Flagged as Malicious(Domain)'] > 1]

# Save to Excel
output_file = os.path.join(output_dir, f"Domain_Response_{current_datetime}.xlsx")
with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
    clean_df.to_excel(writer, sheet_name='Clean', index=False)
    suspicious_df.to_excel(writer, sheet_name='Suspicious', index=False)
    malicious_df.to_excel(writer, sheet_name='Malicious', index=False)

print(f"Output saved to {output_file}")
