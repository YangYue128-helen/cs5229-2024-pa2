#!/usr/bin/env python3
import sys

from scapy.all import *
from scapy.layers.l2 import Ether

class MulticastPkt(Packet):
    name = "multicast"
    fields_desc = [
        BitField("mcast_grp", 0x0000, 16),
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

def get_mac(host_num):
    if host_num == 1:
        return "08:00:00:00:01:11"
    elif host_num == 2:
        return "08:00:00:00:02:22"
    elif host_num == 3:
        return "08:00:00:00:03:33"
    else:
        return "ff:ff:ff:ff:ff:ff"

def main():
    if len(sys.argv)<4:
        print('pass 3 arguments: <multicast group 0/12/13/23> <dst host number> <message content>)')
        exit(1)
    
    mcast_grp = int(sys.argv[1])
    dst_host_num = int(sys.argv[2])
    message_content = str(sys.argv[3])

    dst_host_mac = get_mac(dst_host_num)

    iface = get_if()
    bind_layers(Ether, MulticastPkt, type=0x1234)

    print("sending on interface %s, multicast: %d" % (iface, mcast_grp))
    print("content: %s" % message_content)
    pkt = Ether(src=get_if_hwaddr(iface), dst=dst_host_mac, type=0x1234)
    pkt = pkt / MulticastPkt(mcast_grp=mcast_grp) / Raw(load=message_content)
    # pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
