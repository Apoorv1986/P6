#!/usr/bin/env python
import sys
import struct
import os
import argparse

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw, ICMP, ARP
from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt, addr, interface):
    #if TCP in pkt and pkt[TCP].dport == 1234:
    if (ICMP in pkt) or (ARP in pkt):
        return#
    print "got a packet"
    p=Ether(src="08:00:27:1b:39:12",dst="00:00:00:00:00:02")/IP(src="192.168.0.10",dst=addr)/UDP(dport=9977)/struct.pack('I',2)/pkt
    sendp(p, iface=interface)
    pkt.show2()
    #    hexdump(pkt)
    sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The IP address of the host to use")
    parser.add_argument('interface', type=str, help="The interface of the VM to Agent")
    parser.add_argument('interface_sniff', type=str, help="The interface of the VM to sniff on")
    args = parser.parse_args()
    addr = args.ip_addr
    interface = args.interface
    interface_sniff = args.interface_sniff
    print "Interface: ", interface
    print "Addr: ", addr
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
#    iface = ifaces[0]
    print "sniffing on %s" % interface_sniff
    sys.stdout.flush()
    #sniff(iface = 's1-eth2',
    sniff(iface = str(interface_sniff),
          prn = lambda x: handle_pkt(x, addr, interface))

if __name__ == '__main__':
    main()

