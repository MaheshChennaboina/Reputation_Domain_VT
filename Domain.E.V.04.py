import os
import requests
import pandas as pd
from datetime import datetime

def get_domain_details(api_key, domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': api_key}

    try:
        response = requests.get(url, headers=headers)
        result = response.json()

        if response.status_code == 200:
            malicious_vendors = result['data']['attributes']['last_analysis_stats']['malicious']
            print(f"Domain: {domain} - Malicious Vendors: {malicious_vendors}")
            return malicious_vendors
        else:
            print(f"Error: {result.get('verbose_msg')}")
            return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def save_to_excel(results, output_folder):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_folder, f"result_{timestamp}.xlsx")
    df = pd.DataFrame(results, columns=['Domain', 'Malicious_Vendors'])
    df.to_excel(output_path, index=False)
    print(f"Results saved to: {output_path}")

if __name__ == "__main__":
    api_key = '029455493eb333bf6e839263f7375ceb5a97db5845de1b3646775188a7879269'  # Replace with your VirusTotal API key
    excel_file_path = "input.xlsx"
    output_folder = "Response"

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    results = []

    df = pd.read_excel(excel_file_path)

    for index, row in df.iterrows():
        domain = row['Domain']
        malicious_vendors = get_domain_details(api_key, domain)
        results.append({'Domain': domain, 'Malicious_Vendors': malicious_vendors})

    save_to_excel(results, output_folder)
