#import socket, sys
import os
import socket
#from struct import *

# host to listen on
host = '172.17.182.223'
print "Sistema Operativo: " + os.name

#create an new raw socket and bind it to the NIC
if os.name == "nt":
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))

# Include the IP headers be included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# As Windows is being used, it is needed to send an IOCTL
# to set up promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
	print "modo promiscuo activado"

# read in a single packet
print sniffer.recvfrom(65565)
print "1era parte ready"


# PARSING THE SNIFFED PACKET
#Sniffs only incoming TCP packet
 
# receive packets
while True:
    packet = sniffer.recvfrom(65565)
#packet string from tuple
packet = packet[0]
     
#take first 20 characters for the ip header
ip_header = packet[0:20]

#now unpack them :)
iph = unpack('!BBHHHBBH4s4s' , ip_header)

version_ihl = iph[0]
version = version_ihl >> 4
ihl = version_ihl & 0xF

iph_length = ihl * 4

ttl = iph[5]
protocol = iph[6]
s_addr = socket.inet_ntoa(iph[8]);
d_addr = socket.inet_ntoa(iph[9]);

print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

tcp_header = packet[iph_length:iph_length+20]

#now unpack them :)
tcph = unpack('!HHLLBBHHH' , tcp_header)

source_port = tcph[0]
dest_port = tcph[1]
sequence = tcph[2]
acknowledgement = tcph[3]
doff_reserved = tcph[4]
tcph_length = doff_reserved >> 4

print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

h_size = iph_length + tcph_length * 4
data_size = len(packet) - h_size

#get data from the packet
data = packet[h_size:]
print 'Data : ' + data
print