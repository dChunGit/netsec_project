from scapy.all import send,IP,ICMP, TCP
import csv
import socket
from itertools import groupby 

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
myIP = s.getsockname()[0]
print(myIP)
s.close()

with open("bluekeepips.txt") as ipfile:
  for line in ipfile:
    address = line.strip()
    print(address)

    ip = IP(src=myIP, dst=address)
    SYN = TCP(sport=1040, dport=3389, flags="S", seq=12345)
    send(ip/SYN)

input("Press Enter to continue...")

with open('log.txt') as f:
    lines = f.read().splitlines()
    data = []
    os_data = []
    for line in lines:
      clean_line = line.split("] ")[1]
      try:
        scanned_address = dict(item.split("=", 1) for item in clean_line.split("|"))
        if 'os' in scanned_address:
          if 'Win' in scanned_address['os']:
            server_ip = scanned_address['srv'].split('/')[0]
            if server_ip != myIP:
              data.append(server_ip)
          elif '?' not in scanned_address['os']:
            os_data.append(scanned_address['os'])
      except:
        print(clean_line)

    print(len(data))
    print(len(os_data))
    print(sorted(os_data))

with open('candidates.csv','w') as ipaddresses:
  wr = csv.writer(ipaddresses)
  wr.writerow(data)