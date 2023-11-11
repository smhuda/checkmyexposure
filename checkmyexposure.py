import json
import csv
import time
import socket
from whois import whois
from ipwhois import IPWhois
from requests import get, exceptions

def print_title():
    print('Welcome to Exposure-Check')

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    # Print New Line on Complete
    if iteration == total: 
        print()

def get_whois_info(domain):
    try:
        return str(whois(domain))
    except Exception as e:
        return f"Error retrieving WHOIS information: {e}"

def get_arin_info(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(depth=1)
        return results
    except Exception as e:
        return f"Error retrieving ARIN information: {e}"

def get_crt_sh_certs(domain):
    url = f'https://crt.sh/?q={domain}&output=json'
    try:
        response = get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return f"Error retrieving information from crt.sh: Status code {response.status_code}"
    except exceptions.RequestException as e:
        return f"Error retrieving information from crt.sh: {e}"

def export_results(data, filename, export_format):
    if export_format == 'json':
        with open(f'{filename}.json', 'w') as jsonfile:
            json.dump(data, jsonfile, indent=4)
    elif export_format == 'csv':
        with open(f'{filename}.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for key, value in data.items():
                writer.writerow([key, value])

def main():
    print_title()
    domain = input("Enter the domain: ")
    steps = 3
    step = 0
    
    print_progress_bar(step, steps, prefix='Progress:', suffix='Complete', length=50)
    whois_info = get_whois_info(domain)
    step += 1
    print_progress_bar(step, steps, prefix='Progress:', suffix='Complete', length=50)

    arin_info = get_arin_info(domain)
    step += 1
    print_progress_bar(step, steps, prefix='Progress:', suffix='Complete', length=50)

    crt_sh_certificates = get_crt_sh_certs(domain)
    step += 1
    print_progress_bar(step, steps, prefix='Progress:', suffix='Complete', length=50)
    
    results = {
        "WHOIS Information": whois_info,
        "ARIN Information": arin_info,
        "Certificates": crt_sh_certificates
    }

    print("\nData collection complete. Would you like to export the results? (y/n)")
    export = input().lower()
    if export == 'y':
        print("Please enter the export format (json/csv):")
        export_format = input().lower()
        filename = domain + "_exposure_check"
        export_results(results, filename, export_format)
        print(f"Results exported to {filename}.{export_format}")
    else:
        print("\nCollected Information:")
        print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()

