from scapy.all import send,IP,ICMP, TCP
import csv

ips = ["70.184.71.102", "107.21.240.66", "130.156.111.26", "205.134.187.221", "107.148.154.182",
       "72.194.233.208"]
print(len(ips))
for address in ips:
  ip = IP(src="10.145.58.118", dst=address)
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
    print(data)

with open('ipaddresses.csv','w') as ipaddresses:
  wr = csv.writer(ipaddresses, quoting=csv.QUOTE_ALL)
  wr.writerow(data)