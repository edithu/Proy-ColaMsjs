__doc__ =""" 
La intencion con este codigo es capturar paquetss ICMP sin embargo,
por alguna razon que deconozco no captura paquetes
"""
import socket
import os
import ctypes
import struct
from struct import *
#from ICMPHeader import ICMP

# host to listen
HOST = '172.17.182.223'
print "Sistema Operativo: " + os.name

# Class to represent ICMP Header 
class ICMP(ctypes.Structure):
    _fields_ = [
    ('type',        ctypes.c_ubyte),
    ('code',        ctypes.c_ubyte),
    ('checksum',    ctypes.c_ushort),
    ('unused',      ctypes.c_ushort),
    ('next_hop_mtu',ctypes.c_ushort)
    ]
    # __new__ when it is needed to control the creation of a new instance
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    # __init__ when it is needed to control initialization of a new instance.
    def __init__(self, socket_buffer):
        pass

class ICMPHeader(object):
    # _fields_ = [
    # ('Type',        ctypes.c_ubyte),
    # ('Code',        ctypes.c_ubyte),
    # ('Checksum',    ctypes.c_longlong),
    # ('ID',          ctypes.c_int),
    # ('Seq',         ctypes.c_int),
    # ('Data',        ctypes.c_wchar)
    # ]
    def __init__(self, type=8):
        self.Type     = type # 8 = Echo request ; 0 = Echo reply
        self.Code     = 0
        self.CheckSum = 0
        self.ID       = 0
        self.Seq      = 1
        self.Data     = "!abcdef0123456789!"
    
    def __carry_around_add(self, a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    def __calcCheckSum(self,msg): # http://stackoverflow.com/questions/1767910/checksum-udp-calculation-python
        s = 0
        for i in range(0, len(msg), 2):
            if( i+1 != len(msg) ):
                w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
            else:
                w = (ord(msg[i]) << 8)
            s = self.__carry_around_add(s, w)
        return ~s & 0xffff
        
    def createHeader(self,data,id=-1,seq=-1):
        if(id == -1):
            self.ID += 1
            self.ID %= 65535
        else:
            self.ID = id
        if(seq == -1):
            pass
        else:
            self.Seq = seq
        self.Data = data
        
        firstWord  = self.Type << 24
        firstWord |= self.Code << 16

        secondWord  = self.ID << 16
        secondWord |= self.Seq
        
        tmpMessage = struct.pack("!II", (firstWord|0x0000), secondWord) + self.Data
        self.CheckSum = self.__calcCheckSum(tmpMessage)
        firstWord |= self.CheckSum

        self.Seq += 1

        return struct.pack("!II", firstWord, secondWord) + self.Data, 8 + len(self.Data)

def sniffing(host, win, socket_prot):
    count == 1
    while True: #en vez de True estaba 1
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
        sniffer.bind((host, 0))

        # include the IP headers in the captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # As Windows is being used, it is needed to send an IOCTL
        # to set up promiscuous mode
        if win == 1: 
            sniffer.ioctl(socket.SIO_RCVALL, socket_RCVALL_ON)
        print "modo promiscuo activado"
        # read in a single packet
        print sniffer.recvfrom(65565)
        print "Sniffing ..." + str(count)
        count += 1 
        continue

def main(host):
    if os.name == 'nt':
        sniffing(host, 1, socket.IPPROTO_IP)
    else:
        sniffing(host, 0, socket.IPPROTO_ICMP)

def main():
    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind(( HOST, 0 ))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True: #Estaba 1 en vez de True
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

        #Parsing of IP Packet
        # Create IP structure
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print 'IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
        ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:'\
         + str(s_addr) + ', Destination:' + str(d_addr)

        # Create ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        print "ICMP -> Type:%d, Code:%d" %(icmp_header.type, icmp_header.code) + '\n'
        continue

if __name__ == '__main__':
    main() 

if __name__ == '__main__':
    main(HOST)
