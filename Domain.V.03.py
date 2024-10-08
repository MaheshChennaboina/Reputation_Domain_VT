#Updated the script and it works only on 3.11 version, Use encoding format ISO-8859-1 to solve the issue.
print("[*] Importing Python Modules ... ", end="")
import os, time, json, sys  
from datetime import datetime
import requests, base64, json5 
import traceback
from colorama import init
from colorama import Fore, Back, Style
init()

import pandas as pd
import numpy as np
import concurrent.futures
print("done!")

class VirusTotalScanner:
    def __init__(self, debug_mode, timeout, api_keys_list, Master_CSV_filename, Sorted_Master_CSV_filename, After_Comparison_With_Archive_New_Filename, Threat_Intel_Report_filename):
      
        try:
            os.remove('logs.txt')
        except:
            pass
        self.logs = open("logs.txt", "a+")
        self.timeout       = timeout
        self.api_keys_list = api_keys_list
        self.debug_mode    = debug_mode   # If Enabled then it will write json file of each function
        self.Master_CSV_filename = Master_CSV_filename.replace(" ", "_")+".csv"
        self.Sorted_Master_CSV_filename = Sorted_Master_CSV_filename.replace(" ", "_")+".csv"
        self.After_Comparison_With_Archive_New_Filename = After_Comparison_With_Archive_New_Filename.replace(" ", "_")
        self.Threat_Intel_Report_filename = Threat_Intel_Report_filename.replace(" ", "_")

    def printer(self, log_text, log_type):
        """
        Will Write & Print Logs
        """
        datetime_text = datetime.now().strftime(f"{Fore.WHITE}[Date: %d-%m-%Y] [Time: %H:%M:%S]{Style.RESET_ALL} ")
        
        if log_type == "INFO":
            datetime_text += f'[{Fore.GREEN}{log_type}{Style.RESET_ALL}] '
            print(f'{datetime_text}{log_text}')
        elif log_type == 'ERROR':
            datetime_text += f'[{Fore.YELLOW}{log_type}{Style.RESET_ALL}] '
            print(f'{datetime_text}{log_text}')

        clean_datetime_text = datetime_text.replace(Fore.WHITE, '').replace(Fore.YELLOW, '').replace(Fore.GREEN, '').replace(Fore.RED, '').replace(Style.RESET_ALL, '')
        clean_logs = log_text.replace(Fore.WHITE, '').replace(Fore.YELLOW, '').replace(Fore.GREEN, '').replace(Fore.RED, '').replace(Style.RESET_ALL, '')
        self.logs.write(clean_datetime_text + clean_logs + "\n")

    def start(self):
        # Checking if Report & IOC-Archive-Database folder exist or not, if not, then create them
        if not os.path.exists('Report'):
            os.mkdir('Report')

        if not os.path.exists('IOC-Archive-Database'):
            os.mkdir('IOC-Archive-Database')

        self.printer(f"{Fore.YELLOW}Hit Enter, For selecting {Fore.GREEN}Default Value!{Style.RESET_ALL}", "INFO")
        input_excel_file = input(f"\n[?] Enter Excel file path Containing IOC [Default: Input.xlsx]: ")
        if input_excel_file == "":
            input_excel_file = "Input.xlsx"

        self.archive_excel_file = input(f"[?] Enter Archive Excel file path Containing Old IOC [Default: IOC-Archive-Database/ArchiveIOC.xlsx]: ")
        if self.archive_excel_file == "":
            self.archive_excel_file = "IOC-Archive-Database/ArchiveIOC.xlsx"   

        # For Testing Functions 
        # self.test_ico_functions()
        # sys.exit()

        # Reading Excel & Extracting 'IOC Value' & 'IOC Type' Columns
        df = pd.read_excel(input_excel_file)
        IOC_df = df[['Threat Actor Name','IOC Value', 'IOC Type']]
        
        self.ThreadNumber  = len(self.api_keys_list)  # More API ==> More Speed
        new_api_key_list = []
        for i in range(round(len(IOC_df)/self.ThreadNumber)):   # Doing this in order to make a new api list with exact len() as Total IOCs
            new_api_key_list.extend(self.api_keys_list)
        new_api_key_list = new_api_key_list[:len(IOC_df)]  # Removing Extra APIs
        IOC_df.insert(3, "API", pd.Series(new_api_key_list), True)  # 3==ColumnPosition

        # Replacing NaN to First API Key
        IOC_df['API'] = IOC_df['API'].replace(np.nan, self.api_keys_list[0])
        # IOC_df.to_csv('test.csv', index=False)

        # Multi-Threaded Implementation
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.ThreadNumber)
        futures = [executor.submit(self.scan_IOC, row) for _, row in IOC_df.iterrows()]
        concurrent.futures.wait(futures) 

        # Sorting Master CSV on the basis of Pyramid of Pain
        self.printer(f"{Fore.YELLOW}Sorting Master CSV based on {Fore.GREEN}Pyramid of Pain {Fore.YELLOW}...{Style.RESET_ALL}", "INFO")
        self.sort_csv_based_on_IOC_type()
        self.printer(f"{Fore.GREEN}Done :-){Style.RESET_ALL}", "INFO")

        # Comparison with Archive Excel & Removing Already OLD IOCs
        self.compare_final_data_with_archive()  

        # Deleting MasterCSV & Sorted MasterCSV
        os.remove(self.Master_CSV_filename)
        os.remove(self.Sorted_Master_CSV_filename)

    def test_ico_functions(self):
        """
        This function is made to test these 4 functions
        """
        IOC_hash   = '9aa1f37517458d635eae4f9b43cb4770880ea0ee171e7e4ad155bbdee0cbe732'
        IOC_url    = 'http://www.thechiropractor.vegas/'
        IOC_domain = 'myeeducationplus.com'
        IOC_ipaddr = '45.79.220.27'
        api_key    = self.api_keys_list[0]

        hash_status = self.check_IOC_hash(IOC_hash, api_key)
        url_status = self.check_IOC_url(IOC_url, api_key)
        domain_status = self.check_IOC_domain(IOC_domain, api_key)
        ipaddr_status = self.check_IOC_ipaddr(IOC_ipaddr, api_key)

    def scan_IOC(self, row):    
        ThreatActorName        = row['Threat Actor Name'] 
        IndicatorOfCompromise  = row['IOC Value'].strip() 
        IOC_type               = row['IOC Type']
        api_key                = row['API']

        md5_hash, sha1_hash, sha256_hash = "", "", ""
        domain_communicating_files_result = []
        domain_referrer_files_result = []

        if IOC_type in ['MD5', 'SHA1', 'SHA256']:
            status, md5_hash, sha1_hash, sha256_hash = self.check_IOC_hash(IndicatorOfCompromise, api_key)
        elif IOC_type == 'URL':
            status = self.check_IOC_url(IndicatorOfCompromise, api_key)
            if status == 'Not Found':
                self.printer(f'{Fore.GREEN}Re-Scanning: {Fore.RED}{IndicatorOfCompromise}{Fore.YELLOW} ...{Style.RESET_ALL}', 'INFO')
                scan_id = self.rescan_IOC_url(IndicatorOfCompromise, api_key)   
                if scan_id != None:
                    time.sleep(60) # Sleeping for 60 sec
                    status = self.check_IOC_url(IndicatorOfCompromise, api_key)

            communicating_files_result_list = self.check_IOC_domain_related_files(base64.b64encode(IndicatorOfCompromise.encode()).decode().replace('==', ''), api_key, "communicating_files", "urls")
            if communicating_files_result_list:
                datetime_text = datetime.now().strftime(f"%d-%m-%Y")
                for result_data in communicating_files_result_list:
                    current_status      = result_data[0]
                    current_md5_hash    = result_data[1]
                    current_sha1_hash   = result_data[2]
                    current_sha256_hash = result_data[3]
                    current_result_list = [{
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_md5_hash,  
                        "IOC Type"          : "MD5",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_sha1_hash,
                        "IOC Type"          : "SHA1",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_sha256_hash,
                        "IOC Type"          : "SHA256",
                        "Status"            : current_status},                                
                    ]                    
                    domain_communicating_files_result.extend(current_result_list)

            referrer_files_result_list = self.check_IOC_domain_related_files(base64.b64encode(IndicatorOfCompromise.encode()).decode().replace('==', ''), api_key, "referrer_files", "urls")
            if referrer_files_result_list:
                datetime_text = datetime.now().strftime(f"%d-%m-%Y")
                for result_data in referrer_files_result_list:
                    current_status      = result_data[0]
                    current_md5_hash    = result_data[1]
                    current_sha1_hash   = result_data[2]
                    current_sha256_hash = result_data[3]
                    current_result_list = [{
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_md5_hash,  
                        "IOC Type"          : "MD5",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_sha1_hash,
                        "IOC Type"          : "SHA1",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_sha256_hash,
                        "IOC Type"          : "SHA256",
                        "Status"            : current_status},                                
                    ]                    
                    domain_referrer_files_result.extend(current_result_list)

        elif IOC_type == 'Domain':
            status = self.check_IOC_domain(IndicatorOfCompromise, api_key)
            if status == 'Not Found':
                self.printer(f'{Fore.GREEN}Re-Scanning: {Fore.RED}{IndicatorOfCompromise}{Fore.YELLOW} ...{Style.RESET_ALL}', 'INFO')                
                time.sleep(65) # Sleeping for 65 sec
                status = self.check_IOC_domain(IndicatorOfCompromise, api_key)
            communicating_files_result_list = self.check_IOC_domain_related_files(IndicatorOfCompromise, api_key, "communicating_files", "domains")
            if communicating_files_result_list:
                datetime_text = datetime.now().strftime(f"%d-%m-%Y")
                for result_data in communicating_files_result_list:
                    current_status      = result_data[0]
                    current_md5_hash    = result_data[1]
                    current_sha1_hash   = result_data[2]
                    current_sha256_hash = result_data[3]
                    current_result_list = [{
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_md5_hash,  
                        "IOC Type"          : "MD5",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_sha1_hash,
                        "IOC Type"          : "SHA1",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_sha256_hash,
                        "IOC Type"          : "SHA256",
                        "Status"            : current_status},                                
                    ]                    
                    domain_communicating_files_result.extend(current_result_list)

            referrer_files_result_list = self.check_IOC_domain_related_files(IndicatorOfCompromise, api_key, "referrer_files", "domains")
            if referrer_files_result_list:
                datetime_text = datetime.now().strftime(f"%d-%m-%Y")
                for result_data in referrer_files_result_list:
                    current_status      = result_data[0]
                    current_md5_hash    = result_data[1]
                    current_sha1_hash   = result_data[2]
                    current_sha256_hash = result_data[3]
                    current_result_list = [{
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_md5_hash,  
                        "IOC Type"          : "MD5",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_sha1_hash,
                        "IOC Type"          : "SHA1",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_sha256_hash,
                        "IOC Type"          : "SHA256",
                        "Status"            : current_status},                                
                    ]                    
                    domain_referrer_files_result.extend(current_result_list)

        elif IOC_type == 'IP':
            status = self.check_IOC_ipaddr(IndicatorOfCompromise, api_key)
            communicating_files_result_list = self.check_IOC_domain_related_files(IndicatorOfCompromise, api_key, "communicating_files", "ip_addresses")
            if communicating_files_result_list:
                datetime_text = datetime.now().strftime(f"%d-%m-%Y")
                for result_data in communicating_files_result_list:
                    current_status      = result_data[0]
                    current_md5_hash    = result_data[1]
                    current_sha1_hash   = result_data[2]
                    current_sha256_hash = result_data[3]
                    current_result_list = [{
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_md5_hash,  
                        "IOC Type"          : "MD5",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_sha1_hash,
                        "IOC Type"          : "SHA1",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Communicating_IOC_Hash",
                        "Referral IOC Value": current_sha256_hash,
                        "IOC Type"          : "SHA256",
                        "Status"            : current_status},                                
                    ]                    
                    domain_communicating_files_result.extend(current_result_list)

            referrer_files_result_list = self.check_IOC_domain_related_files(IndicatorOfCompromise, api_key, "referrer_files", "ip_addresses")
            if referrer_files_result_list:
                datetime_text = datetime.now().strftime(f"%d-%m-%Y")
                for result_data in referrer_files_result_list:
                    current_status      = result_data[0]
                    current_md5_hash    = result_data[1]
                    current_sha1_hash   = result_data[2]
                    current_sha256_hash = result_data[3]
                    current_result_list = [{
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_md5_hash,  
                        "IOC Type"          : "MD5",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_sha1_hash,
                        "IOC Type"          : "SHA1",
                        "Status"            : current_status},
                        {
                        "Date"              : datetime_text,
                        "Threat Actor Name" : ThreatActorName,
                        "Parent IOC Value"  : IndicatorOfCompromise,
                        "Referral IOC Type" : "Referrer_IOC_Hash",
                        "Referral IOC Value": current_sha256_hash,
                        "IOC Type"          : "SHA256",
                        "Status"            : current_status},                                
                    ]                    
                    domain_referrer_files_result.extend(current_result_list)            
        else:
            self.printer(f'{Fore.YELLOW}Error: [{Fore.RED}Unknown IOC Type{Fore.YELLOW}]IOC_type: {Fore.RED}{IOC_type}{Style.RESET_ALL}', 'ERROR')

        # Writing Data to Python List        
        if md5_hash != "" and sha1_hash != "" and sha256_hash != "":
            datetime_text = datetime.now().strftime(f"%d-%m-%Y")
            data_list = [{
                "Date"              : datetime_text,
                "Threat Actor Name" : ThreatActorName,
                "Parent IOC Value"  : "",
                "Referral IOC Type" : "",
                "Referral IOC Value": "",
                "IOC Value"         : md5_hash,
                "IOC Type"          : "MD5",
                "Status"            : status},
                {
                "Date"              : datetime_text,
                "Threat Actor Name" : ThreatActorName,
                "Parent IOC Value"  : "",
                "Referral IOC Type" : "",
                "Referral IOC Value": "",                
                "IOC Value"         : sha1_hash,
                "IOC Type"          : "SHA1",
                "Status"            : status},
                {
                "Date"              : datetime_text,
                "Threat Actor Name" : ThreatActorName,
                "Parent IOC Value"  : "",
                "Referral IOC Type" : "",
                "Referral IOC Value": "",                
                "IOC Value"         : sha256_hash,
                "IOC Type"          : "SHA256",
                "Status"            : status},                                
                ]             
        else:
            datetime_text = datetime.now().strftime(f"%d-%m-%Y")
            data_list = [{
                "Date"              : datetime_text,
                "Threat Actor Name" : ThreatActorName,
                "Parent IOC Value"  : "",
                "Referral IOC Type" : "",
                "Referral IOC Value": "",                
                "IOC Value"         : IndicatorOfCompromise,
                "IOC Type"          : IOC_type,
                "Status"            : status,
            }]
        data_list.extend(domain_communicating_files_result)
        data_list.extend(domain_referrer_files_result)
        df = pd.DataFrame(data_list)
        self.write_data_to_csv(self.Master_CSV_filename, df)
        time.sleep(15)   # As Rate Limit for Free API is FOUR PER Minute  (60/4 == 15) 

    def write_data_to_csv(self, filename, df):
        with open(filename, 'a') as f:
            df.to_csv(f, header=f.tell() == 0, index=False, lineterminator='\n') 

    def sort_csv_based_on_IOC_type(self):
        """
        1. URL, 2. Domain, 3. IP, 4. MD5, 5. SHA1, 6. SHA256
        """
        df = pd.read_csv(self.Master_CSV_filename,encoding='ISO-8859-1')

        df_Domain = df.loc[df['IOC Type'] == 'Domain']
        df_URL    = df.loc[df['IOC Type'] == 'URL']
        df_IP     = df.loc[df['IOC Type'] == 'IP']
        df_Hash   = df.loc[ df[ (df['IOC Type'] == 'MD5') | (df['IOC Type'] == 'SHA1') | (df['IOC Type'] == 'SHA256') ].index ]

        frames = [df_Domain, df_URL, df_IP, df_Hash]
        IOC_df = pd.concat(frames)  
        IOC_df.to_csv(self.Sorted_Master_CSV_filename, index=False)

    def compare_final_data_with_archive(self):
        self.printer(f"{Fore.YELLOW}Comparing {Fore.GREEN}Sorted Master Excel{Fore.YELLOW} with {Fore.GREEN}Archive Excel{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        final_archive_ioc_list = []
        df = pd.read_excel(self.archive_excel_file)
        df = df['IOC Value']

        for _, ioc in df.items():
            final_archive_ioc_list.append(ioc.replace('[.]', '.'))

        # Reading Sorted CSV for Deletion of Unwanted IOC (Need to delete IOCs which are already there is Archive)
        IOC_df = pd.read_csv(self.Sorted_Master_CSV_filename)
        for archive_ioc in final_archive_ioc_list:
            index_names = IOC_df[IOC_df['IOC Value'] == archive_ioc].index
            IOC_df.drop(index_names, inplace = True)

        reffer_ioc_df = IOC_df.loc[IOC_df['Parent IOC Value'].notnull()]  # Making a df of Communicating/Reffer files
        reffer_ioc_df = reffer_ioc_df.loc[:, ["Date", "Threat Actor Name", "Parent IOC Value", "Referral IOC Type",	"Referral IOC Value", "IOC Type", "Status"]]

        self.printer(f"{Fore.YELLOW}Removing {Fore.GREEN}Duplicates{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        IOC_Value_column_name = 'IOC Value'
        IOC_df = IOC_df.drop_duplicates(subset=IOC_Value_column_name, keep='first')

        # Removing Any Row whose Value is CSV Header
        IOC_df = IOC_df.drop(IOC_df[IOC_df['Date']              == 'Date'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['Threat Actor Name'] == 'Threat Actor Name'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['IOC Value']         == 'IOC Value'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['IOC Type']          == 'IOC Type'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['Status']            == 'Status'].index)

        DF_Which_NEED_TO_SEND = IOC_df[IOC_df['Status']            == 'McAfee Not Detected']
        DF_Which_NEED_TO_SEND = DF_Which_NEED_TO_SEND.loc[:, ["Date", "Threat Actor Name", "IOC Value", "IOC Type", "Status"]] # Removing 'Parent IOC Value', 'Referral IOC Type', 'Referral IOC Value' columns
        writer = pd.ExcelWriter(self.Threat_Intel_Report_filename+datetime.now().strftime('_%d-%m-%Y_%H_%M_%S')+".xlsx", engine='xlsxwriter')
        # Add a header format.
        workbook  = writer.book
        header_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'fg_color': '#7bb8ed',
            'border': 1})        

        DF_Which_NEED_TO_SEND.to_excel(writer, sheet_name='Report', index=False)
        worksheet = writer.sheets['Report']

        # Header formating
        for col_num, value in enumerate(DF_Which_NEED_TO_SEND.columns.values):
            worksheet.write(0, col_num, value, header_format)
            column_len = DF_Which_NEED_TO_SEND[value].astype(str).str.len().max()
            column_len = max(column_len, len(value)) + 3
            worksheet.set_column(col_num, col_num, column_len)    
        writer._save()

        writer = pd.ExcelWriter(self.After_Comparison_With_Archive_New_Filename+datetime.now().strftime('_%d-%m-%Y_%H_%M_%S')+".xlsx", engine='xlsxwriter')

        # Add a header format.
        workbook  = writer.book
        header_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'fg_color': '#7bb8ed',
            'border': 1})

        for excel_sheet_name in ['FireEye Not Detected', 'Not Found', 'Clean', 'Malicious']:
            temp_df = IOC_df.loc[IOC_df['Status'] == excel_sheet_name]
            temp_df = temp_df.loc[:, ["Date", "Threat Actor Name", "IOC Value", "IOC Type", "Status"]]
            temp_df = temp_df.loc[temp_df['IOC Value'].notnull()]  # IOC Value will be NaN if it is part of 'Referral IOCs'
            if excel_sheet_name == 'FireEye Not Detected':
                excel_sheet_name = 'Not Covered'
            temp_df.to_excel(writer, sheet_name=excel_sheet_name, index=False)
            worksheet = writer.sheets[excel_sheet_name]
            # Header formating
            for col_num, value in enumerate(temp_df.columns.values):
                worksheet.write(0, col_num, value, header_format)
                column_len = temp_df[value].astype(str).str.len().max()
                column_len = max(column_len, len(value)) + 3
                worksheet.set_column(col_num, col_num, column_len)            
        reffer_ioc_df.to_excel(writer, sheet_name="Referral IOCs", index=False)
        worksheet = writer.sheets["Referral IOCs"]
        # Header formating for Referral IOCs

        for col_num, value in enumerate(reffer_ioc_df.columns.values):
            worksheet.write(0, col_num, value, header_format)
            column_len = reffer_ioc_df[value].astype(str).str.len().max()
            column_len = max(column_len, len(value)) + 3
            worksheet.set_column(col_num, col_num, column_len)
        writer._save()
        self.printer(f"{Fore.GREEN}Done :-){Style.RESET_ALL}", "INFO")
 
    def check_IOC_hash(self, ioc_hash, api_key):
        try:            
            md5_hash, sha1_hash, sha256_hash = "", "", ""
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': api_key, 'resource': ioc_hash}
            response = requests.get(url, params=params, timeout=self.timeout)
            if self.debug_mode:
                try:
                    with open('hash.json', 'w') as f:
                        f.write(json5.dumps(response.json(), indent=4)) 
                except:
                    with open('hash.json', 'w') as f:
                        f.write(json5.dumps(response.text, indent=4))
            response = response.json()
            if response['response_code'] != 0 :
                scan_result = response['scans']
                final_scan_summary = response['positives']
                malicous_vendors_count = sum (1 for vendor in scan_result.values() if vendor['detected'])
                if final_scan_summary != 0:
                    # If FireEye is not in scan_result, then status = 'FireEye Not Detected'
                    # If  'FireEye'is not in scan_result, then status = 'FireEye Not Detected'
                    # print(scan_result['McAfee']['result'])
                    if (('FireEye' not in scan_result.keys()) or ('McAfee' not in scan_result.keys()) ):
                        status = 'FireEye Not Detected'
                    # If Both 'FireEye'is IN scan_result, then check if Both are Detecting Given IOC
                    # If Only One Engine is detecting then also set status = 'FireEye Not Detected'

                    elif((scan_result['FireEye']['detected'] != True) or (scan_result['McAfee']['detected'] != True)):
                        status = 'FireEye Not Detected'
                        md5_hash    = response['md5']
                        sha1_hash   = response['sha1']
                        sha256_hash = response['sha256']
                        self.printer(f"{Fore.YELLOW}Scan Result: {Fore.RED}{status}{Fore.YELLOW} [IOC: {Fore.GREEN}{ioc_hash}{Fore.YELLOW}]{Fore.YELLOW}[Malicious Count:{Fore.RED}{malicous_vendors_count}{Fore.YELLOW}]{Style.RESET_ALL}", "INFO") 

                    else:
                        status = 'Malicious'
                        md5_hash    = response['md5']
                        sha1_hash   = response['sha1']
                        sha256_hash = response['sha256']
                        self.printer(f"{Fore.YELLOW}Scan Result: {Fore.RED}{status}{Fore.YELLOW} [IOC: {Fore.GREEN}{ioc_hash}{Fore.YELLOW}]{Style.RESET_ALL}", "INFO")
                else:
                    status = 'Clean'
                    md5_hash    = response['md5']
                    sha1_hash   = response['sha1']
                    sha256_hash = response['sha256']  
                    self.printer(f"{Fore.YELLOW}Scan Result: {Fore.RED}{status}{Fore.YELLOW} [IOC: {Fore.GREEN}{ioc_hash}{Fore.YELLOW}]{Style.RESET_ALL}", "INFO")


            else:
                status = "Not Found"
                self.printer(f"{Fore.YELLOW}Scan Result: {Fore.RED}{status}{Fore.YELLOW} [IOC: {Fore.GREEN}{ioc_hash}{Fore.YELLOW}]{Style.RESET_ALL}", "INFO")
            return status, md5_hash, sha1_hash, sha256_hash
        except Exception as e:
            self.printer(f"{Fore.YELLOW}Error in check_IOC_hash() : {Fore.RED}{e}{Style.RESET_ALL}", "ERROR")
    
if __name__ == "__main__":
    print(f"{Fore.YELLOW}[*] Reading Credentials from {Fore.GREEN}virustotal_conf.json{Fore.YELLOW} file ... {Style.RESET_ALL}", end="")
    try:
        f = open('virustotal_conf.json')
        creds_json = json.load(f)

        debug_mode                 = creds_json["debug_mode"]
        timeout                    = creds_json["timeout"]
        api_keys_list              = creds_json["api_keys_list"]
        Master_CSV_filename        = creds_json["Master_CSV_filename"]
        Sorted_Master_CSV_filename = creds_json["Sorted_Master_CSV_filename"]
        After_Comparison_With_Archive_New_Filename = creds_json["After_Comparison_With_Archive_New_Filename"]
        Threat_Intel_Report_filename = creds_json["Threat_Intel_Report_filename"]
        print("done!")
        print(f"{Fore.GREEN}[+] Sanity Check Has Been Completed!{Style.RESET_ALL}\n")
    except Exception as e:
        print("failed!") 
        print("[!] ERROR: ", e)
        sys.exit()

    test = VirusTotalScanner(debug_mode, timeout, api_keys_list, Master_CSV_filename, Sorted_Master_CSV_filename, After_Comparison_With_Archive_New_Filename, Threat_Intel_Report_filename)
    test.start()
    
