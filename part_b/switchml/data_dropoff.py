#!/usr/bin/env python3
import random
import socket
import sys
import time
import struct
import zlib

from scapy.all import *

# defined in p4 program:
# header switchml_t {
#     bit<16> hostID;
#     bit<16> opCode;
#     bit<32> val0;
#     bit<32> val1;
#     bit<32> val2;
#     bit<32> val3;
#     bit<32> val4;
#     bit<32> val5;
#     bit<32> val6;
#     bit<32> val7;
# }

# const bit<16> TYPE_IPV4 = 0x800;
# const bit<8>  IPV4_UDP_PRON = 0x11;
# const bit<16> SWITCHML_UDP_PORT = 0x3824;
# const bit<32> SWITCH_ML_CAPACITY = 8;
# const bit<32> SWITCH_ML_HOST_NUM = 4;
# const bit<32> SWITCH_IP = 0x0a0000FE;

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

def get_host_id(iface):
    my_ip = get_if_addr(iface)
    if my_ip == '10.0.0.1':
        return 0x0000
    elif my_ip == '10.0.0.2':
        return 0x0001
    elif my_ip == '10.0.0.3':
        return 0x0002
    elif my_ip == '10.0.0.4':
        return 0x0003
    else:
        return None

def main():
    if len(sys.argv)<9:
        print('pass data: val0 val1 val2 val3 val4 val5 val6 val7')
        exit(1)

    data_val0 = int(sys.argv[1])
    data_val1 = int(sys.argv[2])
    data_val2 = int(sys.argv[3])
    data_val3 = int(sys.argv[4])
    data_val4 = int(sys.argv[5])
    data_val5 = int(sys.argv[6])
    data_val6 = int(sys.argv[7])
    data_val7 = int(sys.argv[8])
    print("Sending Gradients:")
    print("    ", str(data_val0), ", ", str(data_val1), ", ", str(data_val2), ", ", str(data_val3), ", ", 
          str(data_val4), ", ", str(data_val5), ", ", str(data_val6), ", ", str(data_val7))

    addr = socket.gethostbyname("10.0.0.254")
    iface = get_if()
    myid = get_host_id(iface) 
    if myid is None: 
        print("Error: Cannot find the ID of this host...")
        exit(1)
    my_op_code = 0x0101
    
    bind_layers(UDP, SWITCHML, sport=0x3824, dport=0x3824)

    print("sending on interface %s to %s" % (iface, str(addr)))
    print("ID of this host: worker%s" % str(myid))

    pkt =  Ether(src=get_if_hwaddr(iface), dst="08:00:00:00:FF:FF", type=0x800)
    pkt = pkt / IP(dst=addr) 
    pkt = pkt / UDP(dport=0x3824, sport=0x3824, chksum=0) 
    pkt = pkt / SWITCHML(
        hostID=myid, opCode=my_op_code, 
        val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
        val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)
    pkt.show()
    res_p = srp1(pkt, iface=iface, verbose=False, timeout=2)
    if not res_p:
        print("Timeout! No message received.")
    else:
        res_p.show()


if __name__ == '__main__':
    main()
