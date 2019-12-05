from scapy.all import send,IP,ICMP, TCP
import csv
import socket

# ips = ["70.184.71.102", "107.21.240.66", "130.156.111.26", "205.134.187.221", "107.148.154.182",
#        "72.194.233.208"]
ips = []
with open("ipaddresses.txt") as ipfile:
    ips = ipfile.read().splitlines()

print(ips)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
myIP = s.getsockname()[0]
print(myIP)
s.close()
for address in ips:
  ip = IP(src=myIP, dst=address)
  SYN = TCP(sport=1040, dport=3389, flags="S", seq=12345)
  send(ip/SYN)

input("Press Enter to continue...")

with open('log.txt') as f:
    lines = f.read().splitlines()
    data = set()
    for line in lines:
      clean_line = line.split("] ")[1]
      try:
        scanned_address = dict(item.split("=", 1) for item in clean_line.split("|"))
        if 'os' in scanned_address:
          if 'Win' in scanned_address['os']:
            server_ip = scanned_address['srv'].split('/')[0]
            if server_ip in ips:
              data.add(server_ip)
      except:
        print(clean_line)
    print(sorted(data))

with open('candidates.csv','w') as ipaddresses:
  wr = csv.writer(ipaddresses, quoting=csv.QUOTE_ALL)
  wr.writerow(data)