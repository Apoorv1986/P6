#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import binascii

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
sys.setrecursionlimit(10000)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    #addr = socket.gethostbyname(sys.argv[1])
    #iface = get_if()
#    iface = "s1-eth1"
    iface = "enp0s8"
 #print "sending on interface %s to %s" % (iface, str(addr))
    #pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    #pkt = pkt /IP(ttl=3,dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    #pkt.show2()
#    print(type(sys.argv[1]))
    
    # use unhexlify of hex argument passed but cut away the b'' 
    # to convert to bytes again
    pkt = binascii.unhexlify(sys.argv[1][2:len(sys.argv[1])-1]) 
    
    file_t=open("packet.txt", "a")
    file_t.write("packet: %s \n" % len(pkt))
    file_t.close()
    pkt = Ether(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
