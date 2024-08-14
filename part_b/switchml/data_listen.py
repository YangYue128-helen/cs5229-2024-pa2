#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import *

class SWITCHML(Packet):
    name = "SwitchML"
    fields_desc = [
        BitField("hostID", 0, 16),
        BitField("opCode", 0, 16),
        BitField("val0", 0, 32),
        BitField("val1", 0, 32),
        BitField("val2", 0, 32),
        BitField("val3", 0, 32),
        BitField("val4", 0, 32),
        BitField("val5", 0, 32),
        BitField("val6", 0, 32),
        BitField("val7", 0, 32),
    ]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_packet(packet):
    if UDP in packet and packet[UDP].dport == 0x3824 and SWITCHML in packet:
        print("Received a SWITCHML packet")
        packet.show2()
    else:
        print("Received a packet that is not SWITCHML")

def main():
    bind_layers(UDP, SWITCHML, sport=0x3824, dport=0x3824)
    iface = get_if()
    print(f"Listening on interface {iface}")
    sniff(iface=iface, prn=handle_packet)


if __name__ == '__main__':
    main()
