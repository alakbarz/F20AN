#!/usr/bin/python3
# ’U’: URG bit
# ’A’: ACK bit
# ’P’: PSH bit
# ’R’: RST bit
# ’S’: SYN bit
# ’F’: FIN bit

from scapy.all import *

x_ip = "10.0.2.8"
x_port = 514

srv_ip = "10.0.2.15"
srv_port = 1023

ip = IP(src=srv_ip, dst=x_ip)
tcp = TCP(sport=srv_port, dport=x_port)
tcp.flags = "S"

packet = ip/tcp

if tcp.flags == "S":
	print("Sending SYN")

ls(packet)
send(packet, verbose = 0)