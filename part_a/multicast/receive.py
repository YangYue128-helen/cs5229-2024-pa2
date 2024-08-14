#!/usr/bin/env python3
import sys
from scapy.all import *
from scapy.layers.l2 import Ether

class MulticastPkt(Packet):
    name = "multicast"
    fields_desc = [
        BitField("mcast_grp", 0x0000, 16)
    ]

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def get_host(host_mac):
    if host_mac == "08:00:00:00:01:11":
        return 1
    elif host_mac == "08:00:00:00:02:22":
        return 2
    elif host_mac == "08:00:00:00:03:33":
        return 3
    else:
        return -1

def handle_packet(pkt):
    pkt.show2()
    if MulticastPkt in pkt and pkt[Ether].type == 0x1234:
        mcast_pkt = pkt[MulticastPkt]
        payload = pkt[Raw].load if Raw in pkt else b''
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        host_num = get_host(src_mac)
        print(f"Received packet from host {host_num}")
        print(f"src MAC {src_mac}")
        print(f"dst MAC {dst_mac}")
        print(f"Multicast: {mcast_pkt.mcast_grp}")
        print(f"Message content: {payload.decode('utf-8', errors='ignore')}")
        print()

def main():
    iface = get_if()
    print(f"Listening on {iface}")
    bind_layers(Ether, MulticastPkt, type=0x1234)
    sniff(iface=iface, prn=handle_packet, filter="ether proto 0x1234")

if __name__ == '__main__':
    main()
