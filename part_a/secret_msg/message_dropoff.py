#!/usr/bin/env python3
import random
import socket
import sys
import time
import struct
import zlib

from scapy.all import *

# defined in p4 program:
# header secret_t {
#     bit<32> hostID;
#     bit<32> salt;
#     bit<32> pw_hash;
#     bit<16> opCode;
#     bit<16> mailboxNum;
#     bit<32> message;
# }

class SECRET(Packet):
    name = "Secret"
    fields_desc = [
        BitField("hostID", 0, 32),
        BitField("salt", 0, 32),
        BitField("pw_hash", 0, 32),
        BitField("opCode", 0, 16),
        BitField("mailboxNum", 0, 16),
        BitField("message", 0, 32)
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
        return 0x0001
    elif my_ip == '10.0.0.2':
        return 0x0002
    elif my_ip == '10.0.0.3':
        return 0x0003
    else:
        return None

def get_password(id):
    if id == 0x0001:
        return b"00015229"
    elif id == 0x0002:
        return b"00025229"
    elif id == 0x0003:
        return b"00035229"
    else: 
        return None

def main():
    if len(sys.argv)<3:
        print('pass 2 arguments: <mailbox number> "<message>"')
        exit(1)

    mailboxNum = int(sys.argv[1])
    message = int.from_bytes(bytes(sys.argv[2],'UTF-8'), byteorder='big')

    addr = socket.gethostbyname("10.0.0.254")
    iface = get_if()
    myid = get_host_id(iface) 
    if myid is None: 
        print("Error: Cannot find the ID of this host...")
        return
    mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
    if mypassword is None: 
        print("Error: Cannot find the password of this host...")
        return
    salt = int(time.time())
    password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))
    
    bind_layers(UDP, SECRET, sport=0xFFFF, dport=0xFFFF)

    print("sending on interface %s to %s" % (iface, str(addr)))
    print("ID of this host: %s" % str(myid))

    pkt =  Ether(src=get_if_hwaddr(iface), dst="08:00:00:00:FF:FF", type=0x800)
    pkt = pkt / IP(dst=addr) 
    pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
    pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=1, mailboxNum=mailboxNum, message=message)
    pkt.show()
    res_p = srp1(pkt, iface=iface, verbose=False, timeout=2)
    if not res_p:
        print("Timeout! No message received.")
    else:
        res_p.show()


if __name__ == '__main__':
    main()
