import os
import requests
import pandas as pd
from datetime import datetime
import json

def load_api_keys(file_path):
    with open(file_path) as f:
        api_keys = json.load(f)
    return api_keys.get('api_keys', [])

def get_domain_details(api_key, domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': api_key}

    try:
        response = requests.get(url, headers=headers)
        result = response.json()
        
        if response.status_code == 200:
            whois_info = result['data']['attributes']['whois']
            data_strings = list(["Create date: ", "Creation Date: "])
            malicious_vendors = result['data']['attributes']['last_analysis_stats']['malicious']
            for data in data_strings:
                create_date_index = whois_info.find(data)
                if create_date_index >= 0:
                    break
            if create_date_index != -1:
                create_date_start = create_date_index + len("Creation Date: ")
                create_date_end = create_date_start + 10
                create_date = whois_info[create_date_start:create_date_end].split()[0]
                print(f"Create Date: {create_date}")
                print(f"Domain: {domain}.....Processing....done!")

                print(f"Number of Security Vendors Flagged as Malicious: {malicious_vendors}")

                return create_date, malicious_vendors
            else:
                print("Create date not found in the whois information.")
                return "unknown", malicious_vendors 

        else:
            print(f"Error: {result.get('verbose_msg')}")
            return None, None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None, None

def save_to_excel(results, output_folder):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_folder, f"result_{timestamp}.xlsx")
    df = pd.DataFrame(results, columns=['Domain', 'Create_Date', 'Malicious_Vendors'])
    df.to_excel(output_path, index=False)
    print(f"Results saved to: {output_path}")

if __name__ == "__main__":
    api_keys_file = "api_keys.json"
    excel_file_path = "input.xlsx"
    output_folder = "Response"

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    results = []
    api_keys = load_api_keys(api_keys_file)

    df = pd.read_excel(excel_file_path)

    for index, row in df.iterrows():
        domain = row['Domain']
        for api_key in api_keys:
            create_date, malicious_vendors = get_domain_details(api_key, domain)
            if create_date is not None and malicious_vendors is not None:
                results.append({'Domain': domain, 'Create_Date': create_date, 'Malicious_Vendors': malicious_vendors})
                break  # Break the loop once a valid result is obtained using one API key

    save_to_excel(results, output_folder)
