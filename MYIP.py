import requests

def get_domain_information(api_key, domain):
    url = f'https://api.threatbook.io/v1/domain/query?apikey={api_key}&resource={domain}'

    try:
        response = requests.get(url)
        result = response.json()
        print(response)
        if response.status_code == 200:
            if 'data' in result and result['data']:
                data = result['data']
                print(f"Domain: {domain}")
                print(f"First Seen: {data.get('first_seen')}")
                print(f"Last Seen: {data.get('last_seen')}")
                print(f"Risk Level: {data.get('risk_level')}")

                # Add more information as needed
            else:
                print(f"Domain information not found in the API response.")
        else:
            print(f"Error: {result.get('error')}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    threatbook_api_key = 'd6ebe18dac304f719ea4be8d64b034645b2de25a50da4e5fbd6d16873acf53ab'
    domain_to_check = 'nrgtik.mx'

    get_domain_information(threatbook_api_key, domain_to_check)
