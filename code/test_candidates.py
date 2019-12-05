import csv, sys
from ipwhois import IPWhois
import ScannerV2

with open('candidates.csv', 'r') as candidates:
    reader = csv.reader(candidates)
    ip_list = list(reader)
    
print(ip_list)

count = 0
offline_count = 0
vuln_count = 0
patched_count = 0
offline_dict = {}
patched_dict = {}
vuln_dict = {}

for ip in ip_list:
    ip = ip[5]
    
    print('Testing ' + ip)
    
    whois = IPWhois(ip)
    info = whois.lookup_rdap()
    
    if(ScannerV2.check_rdp_service(ip)):
        if(ScannerV2.start_rdp_connection([ip])):
            vuln_count = vuln_count + 1
            vuln_dict[ip] = info
        else:
            patched_count = patched_count + 1
            patched_dict[ip] = info
    else:
        offline_count = offline_count + 1
        offline_dict[ip] = info

    count = count + 1
    
print('\nWe found ' + str(vuln_count) + ' vulnerable IP addresses:')
for key in vuln_dict:
    print(key)
    
print('\nWe found ' + str(patched_count) + ' patched IP addresses:')
for key in patched_dict:
    print(key)
    
print('\nWe found ' + str(offline_count) + ' offline IP addresses:')
for key in offline_dict:
    print(key)
