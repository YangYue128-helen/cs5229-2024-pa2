#!/usr/bin/env python3

# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Andy Fingerhut, andy.fingerhut@gmail.com

import os
import logging

import ptf
import ptf.testutils as tu
from ptf.base_tests import BaseTest
import p4runtime_sh.shell as sh
import p4runtime_shell_utils as p4rtutil

# Links to many Python methods useful when writing automated tests:

# The package `ptf.testutils` contains many useful Python methods for
# writing automated tests, some of which are demonstrated below with
# calls prefixed by the local alias `tu.`.  You can see the
# definitions for all Python code in this package, including some
# documentation for these methods, here:

# https://github.com/p4lang/ptf/blob/master/src/ptf/testutils.py


######################################################################
# Configure logging
######################################################################

# Note: I am not an expert at configuring the Python logging library.
# Recommendations welcome on improvements here.

# The effect achieved by the code below seems to be that many DEBUG
# and higher priority logging messages go to the console, and also to
# a file named 'ptf.log'.  Some of the messages written to the
# 'ptf.log' file do not go to the console, and appear to be created
# from within the ptf library.

logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Examples of some kinds of calls that can be made to generate
# logging messages.
#logger.debug("10 logger.debug message")
#logger.info("20 logger.info message")
#logger.warn("30 logger.warn message")
#logger.error("40 logger.error message")
#logging.debug("10 logging.debug message")
#logging.info("20 logging.info message")
#logging.warn("30 logging.warn message")
#logging.error("40 logging.error message")

class SecretTest(BaseTest):
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        logging.debug("SecretTest.setUp()")
        grpc_addr = tu.test_param_get("grpcaddr")
        if grpc_addr is None:
            grpc_addr = 'localhost:9559'
        p4info_txt_fname = tu.test_param_get("p4info")
        p4prog_binary_fname = tu.test_param_get("config")
        sh.setup(device_id=0,
                 grpc_addr=grpc_addr,
                 election_id=(0, 1), # (high_32bits, lo_32bits)
                 config=sh.FwdPipeConfig(p4info_txt_fname, p4prog_binary_fname),
                 verbose=False)
         
        # Insert table entry
        # Forward Table
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.1"
        te.action['port'] = "1"
        te.insert()
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.2"
        te.action['port'] = "2"
        te.insert()
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.3"
        te.action['port'] = "3"
        te.insert()

        # Password Table
        te = sh.TableEntry('password_check')(action='check_password')
        te.match['hdr.secret.hostID'] = "1"
        te.action['stored_password'] = "2195217097"
        te.insert()
        te = sh.TableEntry('password_check')(action='check_password')
        te.match['hdr.secret.hostID'] = "2"
        te.action['stored_password'] = "3312984089"
        te.insert()
        te = sh.TableEntry('password_check')(action='check_password')
        te.match['hdr.secret.hostID'] = "3"
        te.action['stored_password'] = "4162324905"
        te.insert()

    def tearDown(self):
        logging.debug("SecretTest.tearDown()")
        sh.teardown()

class FwdTest(SecretTest):
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.2'

        ig_port = 1
        eg_port = 2

        # IP connectivity between h1 and h2.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_dst_addr, ip_dst=ip_src_addr)
        tu.send_packet(self, eg_port, pkt)
        tu.verify_packets(self, pkt, [ig_port])

from scapy.all import *
import zlib
import struct

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

bind_layers(UDP, SECRET, sport=0xFFFF, dport=0xFFFF)

def get_host_id(my_ip):
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
    elif id == 0x0002:
        return b"00035229"
    else: 
        return None

# Clear Test Case 1
class NonSwitchIpTest(SecretTest):
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.2'

        ig_port = 1
        eg_port = 2

        # IP connectivity between h1 and h2.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_dst_addr, ip_dst=ip_src_addr)
        tu.send_packet(self, eg_port, pkt)
        tu.verify_packets(self, pkt, [ig_port])

        # DropOff but wrong destination IP
        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.253'
        ig_port = 1

        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))


        pkt = Ether() 
        pkt = pkt /IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF) 
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x1, mailboxNum=0, message=0xdeadbeef)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_no_other_packets(self) # should be dropped

        # PickUp but wrong destination IP
        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '1.1.1.1'
        ig_port = 2

        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether() 
        pkt = pkt /IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF) 
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x2, mailboxNum=0, message=0)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_no_other_packets(self) # should be dropped

# Clear Test Case 2
class NonSecretUdpTest(SecretTest):
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.2'

        ig_port = 1
        eg_port = 2

        # IP connectivity between h1 and h2.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_dst_addr, ip_dst=ip_src_addr)
        tu.send_packet(self, eg_port, pkt)
        tu.verify_packets(self, pkt, [ig_port])
        
        # DropOff but wrong UDP dst port
        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.254'
        ig_port = 1

        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether() 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFE, sport=0xFFFF) 
        pkt = pkt/ SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x1, mailboxNum=1, message=0xdeadbeef)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_no_other_packets(self) # should be dropped

        # PickUp but wrong src UDP port
        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.254'
        ig_port = 2

        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))


        pkt = Ether() 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xEEEE) 
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x2, mailboxNum=1, message=0)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_no_other_packets(self) # should be dropped

# Clear Test Case 3
class WrongPasswordTest(SecretTest):
    def runTest(self):
                # DropOff
        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.254'
        ig_port = 1

        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(b"omgwhat?") & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ee:dd:cc:bb:aa') 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr)
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0)
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x1, mailboxNum=4, message=0xdeadbeef)
        tu.send_packet(self, ig_port, pkt)

        exp_pkt = Ether(dst='aa:bb:cc:dd:ee:ff', src='ff:ee:dd:cc:bb:aa')
        exp_pkt = exp_pkt / IP(dst=ip_src_addr, src=ip_dst_addr) 
        exp_pkt = exp_pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0)
        exp_pkt = exp_pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x2333, mailboxNum=4, message=0xdeadbeef)
        tu.verify_packets(self, exp_pkt, [ig_port])

# Clear Test Case 4
class DropOffPickUpTest(SecretTest):
    def runTest(self):
        # DropOff
        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.254'
        ig_port = 1
        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ee:dd:cc:bb:aa') 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x1, mailboxNum=2, message=0xdeadbeef)
        tu.send_packet(self, ig_port, pkt)

        exp_pkt = Ether(dst='aa:bb:cc:dd:ee:ff', src='ff:ee:dd:cc:bb:aa') 
        exp_pkt = exp_pkt / IP(dst=ip_src_addr, src=ip_dst_addr) 
        exp_pkt = exp_pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        exp_pkt = exp_pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0xFFFF, mailboxNum=2, message=0xdeadbeef)
        tu.verify_packets(self, exp_pkt, [ig_port])

        # PickUp
        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.254'
        ig_port = 2
        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ee:dd:cc:bb:aa') 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0)
        pkt = pkt/ SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x2, mailboxNum=2, message=0x0)
        tu.send_packet(self, ig_port, pkt)

        exp_pkt = Ether(dst='aa:bb:cc:dd:ee:ff', src='ff:ee:dd:cc:bb:aa') 
        exp_pkt = exp_pkt / IP(dst=ip_src_addr, src=ip_dst_addr) 
        exp_pkt = exp_pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        exp_pkt = exp_pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0xFFFF, mailboxNum=2, message=0xdeadbeef)
        tu.verify_packets(self, exp_pkt, [ig_port])

# Hidden Test case 1

# Clear Test Case 5
class DropOffMutatePickUpTest(SecretTest):
    def runTest(self):
        # DropOff
        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '10.0.0.254'
        ig_port = 1
        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ee:dd:cc:bb:aa') 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x1, mailboxNum=8, message=0xdeadbeef)
        tu.send_packet(self, ig_port, pkt)

        exp_pkt = Ether(dst='aa:bb:cc:dd:ee:ff', src='ff:ee:dd:cc:bb:aa') 
        exp_pkt = exp_pkt / IP(dst=ip_src_addr, src=ip_dst_addr) 
        exp_pkt = exp_pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        exp_pkt = exp_pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0xFFFF, mailboxNum=8, message=0xdeadbeef)
        tu.verify_packets(self, exp_pkt, [ig_port])

        # Mutate
        os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/modify_state_cmd > /dev/null")

        # PickUp
        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.254'
        ig_port = 2
        salt = int(time.time())
        myid = get_host_id(ip_src_addr)
        mypassword = struct.pack('!I', zlib.crc32(get_password(myid)) & 0xFFFFFFFF)
        password_hash = zlib.crc32(bytes(a & b for a, b in zip(struct.pack('!I', salt & 0xFFFFFFFF), mypassword)))

        pkt = Ether(src='aa:bb:cc:dd:ee:ff', dst='ff:ee:dd:cc:bb:aa') 
        pkt = pkt / IP(src=ip_src_addr, dst=ip_dst_addr) 
        pkt = pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        pkt = pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x2, mailboxNum=8, message=0x0)
        tu.send_packet(self, ig_port, pkt)

        exp_pkt = Ether(dst='aa:bb:cc:dd:ee:ff', src='ff:ee:dd:cc:bb:aa') 
        exp_pkt = exp_pkt / IP(dst=ip_src_addr, src=ip_dst_addr) 
        exp_pkt = exp_pkt / UDP(dport=0xFFFF, sport=0xFFFF, chksum=0) 
        exp_pkt = exp_pkt / SECRET(hostID=myid, salt=salt, pw_hash=password_hash, opCode=0x0, mailboxNum=8, message=0x0)
        tu.verify_packets(self, exp_pkt, [ig_port])

# Hidden Test case 2