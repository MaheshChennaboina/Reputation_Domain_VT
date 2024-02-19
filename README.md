# Domain Reputation Analyzer

## Overview
This Python script analyzes domain reputation using the VirusTotal API. It takes a list of domain names from an input Excel file, queries the VirusTotal API for each domain, retrieves information about the creation date, malicious vendors, apex domain, and IP address, and then saves the results to an output Excel file. It also applies conditional formatting to highlight rows where the number of malicious vendors is zero.

## Dependencies
- Python 3.x
- Pandas
- Requests
- Openpyxl
- Tldextract

## How to Use
1. Ensure that all dependencies are installed.
2. Prepare an Excel file named "input.xlsx" containing a list of domain names in the first column.
3. Create a file named "api_keys.json" containing your VirusTotal API keys in the following format:
   ```json
   {
       "api_keys": [
           "your_api_key_here"
       ]
   }
You can include multiple API keys in the list.
4. Run the script. The results will be saved in a file named "result_<timestamp>.xlsx" in the "Response" folder.

## Functions
load_api_keys(file_path): Loads the VirusTotal API keys from the specified file.
get_domain_details(api_key, domain): Queries the VirusTotal API to get details about a domain.
save_to_excel(results, output_folder): Saves the analysis results to an Excel file and applies conditional formatting.
determine_final_verdict(malicious_vendors): Determines the final verdict based on the number of malicious vendors.
Conditional Formatting
The script applies conditional formatting to highlight rows where the number of malicious vendors is zero. It fills the entire row with a green color.

## Example Usage
python domain_reputation_analyzer.py

## Output
The script generates an Excel file named "result_<timestamp>.xlsx" containing the analysis results. Rows with zero malicious vendors are highlighted in green.
