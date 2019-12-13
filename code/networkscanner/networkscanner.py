from scapy.all import send,IP,ICMP, TCP
import csv
import socket

# ips = ["70.184.71.102", "107.21.240.66", "130.156.111.26", "205.134.187.221", "107.148.154.182",
#        "72.194.233.208"]
# ips = []
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
myIP = s.getsockname()[0]
print(myIP)
s.close()

# with open("bluekeepips.txt") as ipfile:
#   for line in ipfile:
#     address = line.strip()
#     print(address)

#     ip = IP(src=myIP, dst=address)
#     SYN = TCP(sport=1040, dport=3389, flags="S", seq=12345)
#     send(ip/SYN)

# input("Press Enter to continue...")

with open('log.txt') as f:
    lines = f.read().splitlines()
    data = []
    for line in lines:
      clean_line = line.split("] ")[1]
      try:
        scanned_address = dict(item.split("=", 1) for item in clean_line.split("|"))
        if 'os' in scanned_address:
          if 'Win' in scanned_address['os']:
            server_ip = scanned_address['srv'].split('/')[0]
            if server_ip != myIP:
              data.append(server_ip)
            # else:
            #   print(scanned_address)
          else:
            print(scanned_address)
      except:
        print(clean_line)

    print(len(data))
    # print(sorted(data))

with open('candidates.csv','w') as ipaddresses:
  wr = csv.writer(ipaddresses)
  wr.writerow(data)