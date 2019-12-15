import csv, sys, requests
from ipwhois import IPWhois
import ScannerV2
from func_timeout import func_timeout, FunctionTimedOut

def info(string):
    print("[ \033[32m+\033[0m ] {}".format(string))    

def error(string):
    print("[ \033[31m!\033[0m ] {}".format(string))

with open('candidates.csv', 'r') as candidates:
    reader = csv.reader(candidates)
    ip_list = list(reader)

count = 0
offline_count = 0
vuln_count = 0
patched_count = 0
offline_dict = {}
patched_dict = {}
vuln_dict = {}
results = []

def do_scan(ip, count, offline_count, vuln_count, patched_count, offline_dict, patched_dict, vuln_dict, metadata, writer):
    if(ScannerV2.check_rdp_service(ip)):
        if(ScannerV2.start_rdp_connection([ip])):
            metadata['state'] = 'vulnerable'
            vuln_count = vuln_count + 1
            vuln_dict[ip] = metadata
        else:
            metadata['state'] = 'patched'
            patched_count = patched_count + 1
            patched_dict[ip] = metadata
    else:
        metadata['state'] = 'offline'
        offline_count = offline_count + 1
        offline_dict[ip] = metadata

    count = count + 1
    writer.writerow(metadata)
    
    return count, offline_count, vuln_count, patched_count, offline_dict, patched_dict, vuln_dict


with open('results.csv', mode='wb') as csv_file:
    fieldnames = ['ip', 'state', 'whois_country', 'whois_info', 'shodan_country', 'shodan_os', 'shodan_vulns', 'shodan_bluekeep']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()

    for ip in ip_list[0]:
        
        print('Testing ' + str(ip))
        
        whois = IPWhois(ip)
        try:
            info = whois.lookup_rdap()
        except Exception as e:
            error("unable to lookup: {}".format(e))
            continue
            
        try:    
            shodan = requests.get('https://api.shodan.io/shodan/host/' + ip + '?key=m10h7LhfV2VyB8XjTLf0rRss1Ol0B7FT').json()
        except Exception as e:
            error("shodan api call failed: {}".format(e))
            continue
        
        vulns = shodan.get('vulns')
        bluekeep = False
        if vulns is not None and 'CVE-2019-0708' in vulns:
            bluekeep = True
        
        metadata = {
            'ip': ip,
            'state': 'unknown',
            'whois_country': info.get('asn_country_code'),
            'whois_info': info.get("network").get("name"),
            'shodan_country': shodan.get('country_code'),
            'shodan_os': shodan.get('os'),
            'shodan_vulns': vulns,
            'shodan_bluekeep': bluekeep
        }
        
        try:
            count, offline_count, vuln_count, patched_count, offline_dict, patched_dict, vuln_dict = func_timeout(30, do_scan, args=(ip, count, offline_count, vuln_count, patched_count, offline_dict, patched_dict, vuln_dict ,metadata, writer))
        except FunctionTimedOut as e:
            error("unable to complete connection: {}".format(e))
            continue
        
    
print('\nWe found ' + str(vuln_count) + ' vulnerable IP addresses:')
for key in vuln_dict:
    print(key)
    
print('\nWe found ' + str(patched_count) + ' patched IP addresses:')
for key in patched_dict:
    print(key)
    
print('\nWe found ' + str(offline_count) + ' offline IP addresses:')
for key in offline_dict:
    print(key)
    

