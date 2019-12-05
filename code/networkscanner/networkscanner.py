from scapy.all import send,IP,ICMP, TCP

ips = ["205.134.187.221", "107.21.240.66"]
for address in ips:
  ip = IP(src="10.145.58.118", dst=address)
  SYN = TCP(sport=1040, dport=3389, flags="S", seq=12345)
  send(ip/SYN)

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