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

class SwitchMLTest(BaseTest):
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        logging.debug("SwitchMLTest.setUp()")
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
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.4"
        te.action['port'] = "4"
        te.insert()

        # Port to host Table
        te = sh.TableEntry('port_to_host')(action='set_host')
        te.match['standard_metadata.egress_port'] = "1"
        te.action['eth_addr'] = "08:00:00:00:01:11"
        te.action['ip_addr'] = "10.0.0.1"
        te.action['host_id'] = "0"
        te.insert()
        te = sh.TableEntry('port_to_host')(action='set_host')
        te.match['standard_metadata.egress_port'] = "2"
        te.action['eth_addr'] = "08:00:00:00:02:22"
        te.action['ip_addr'] = "10.0.0.2"
        te.action['host_id'] = "1"
        te.insert()
        te = sh.TableEntry('port_to_host')(action='set_host')
        te.match['standard_metadata.egress_port'] = "3"
        te.action['eth_addr'] = "08:00:00:00:03:33"
        te.action['ip_addr'] = "10.0.0.3"
        te.action['host_id'] = "2"
        te.insert()
        te = sh.TableEntry('port_to_host')(action='set_host')
        te.match['standard_metadata.egress_port'] = "4"
        te.action['eth_addr'] = "08:00:00:00:04:44"
        te.action['ip_addr'] = "10.0.0.4"
        te.action['host_id'] = "3"
        te.insert()
        

        te = sh.MulticastGroupEntry(1)
        te.add(1, 1).add(2, 1).add(3, 1).add(4, 1)
        te.insert()

    def tearDown(self):
        logging.debug("SwitchMLTest.tearDown()")
        sh.teardown()

class L3TCPFwdTest(SwitchMLTest):
    def runTest(self):
        mac_addresses = ['08:00:00:00:01:11', '08:00:00:00:02:22', '08:00:00:00:03:33', '08:00:00:00:04:44']
        ip_addresses = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        ports = [1, 2, 3, 4]

        for i in range(0, len(mac_addresses)):
            for j in range(0, len(mac_addresses)):
                in_smac = mac_addresses[i]
                in_dmac = mac_addresses[j]

                ip_src_addr = ip_addresses[i]
                ip_dst_addr = ip_addresses[j]

                ig_port = ports[i]
                eg_port = ports[j]

                # IP connectivity between h1 -> h2.
                pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                        ip_src=ip_src_addr, ip_dst=ip_dst_addr)
                tu.send_packet(self, ig_port, pkt)
                tu.verify_packets(self, pkt, [eg_port])

                # IP connectivity between h2 -> h1.
                pkt = tu.simple_tcp_packet(eth_src=in_dmac, eth_dst=in_smac,
                                        ip_src=ip_dst_addr, ip_dst=ip_src_addr)
                tu.send_packet(self, eg_port, pkt)
                tu.verify_packets(self, pkt, [ig_port])

class L3UDPFwdTest(SwitchMLTest):
    def runTest(self):
        mac_addresses = ['08:00:00:00:01:11', '08:00:00:00:02:22', '08:00:00:00:03:33', '08:00:00:00:04:44']
        ip_addresses = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        ports = [1, 2, 3, 4]

        for i in range(0, len(mac_addresses)):
            for j in range(0, len(mac_addresses)):
                in_smac = mac_addresses[i]
                in_dmac = mac_addresses[j]

                ip_src_addr = ip_addresses[i]
                ip_dst_addr = ip_addresses[j]

                ig_port = ports[i]
                eg_port = ports[j]

                # IP connectivity between h1 -> h2.
                pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                        ip_src=ip_src_addr, ip_dst=ip_dst_addr)
                tu.send_packet(self, ig_port, pkt)
                tu.verify_packets(self, pkt, [eg_port])

                # IP connectivity between h1 -> h2.
                pkt = tu.simple_tcp_packet(eth_src=in_dmac, eth_dst=in_smac,
                                        ip_src=ip_dst_addr, ip_dst=ip_src_addr)
                tu.send_packet(self, eg_port, pkt)
                tu.verify_packets(self, pkt, [ig_port])

from scapy.all import *
import zlib
import struct

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

bind_layers(UDP, SWITCHML, sport=0x3824, dport=0x3824)

def get_host_id(my_ip):
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
    
class DropoffTest(SwitchMLTest):
    # Simply drop off one data packet
    def runTest(self):
        gradient = (1, 2, 3, 4, 5, 6, 7, 8)
        host_mac = '08:00:00:00:01:11'
        host_ip = '10.0.0.1'
        host_port = 1
        host_id = get_host_id(host_ip)
        host_op_code = 0x0101
        data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradient

        # data packet
        pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
        pkt = pkt / IP(src=host_ip, dst="10.0.0.254") 
        pkt = pkt / UDP(dport=0x3824, sport=0x3824, chksum=0) 
        pkt = pkt / SWITCHML(
            hostID=host_id, opCode=host_op_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.send_packet(self, host_port, pkt)

        success_code = 0xFFFF
        exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
        exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
        exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
        exp_pkt = exp_pkt / SWITCHML(
            hostID=host_id, opCode=success_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.verify_packet(self, exp_pkt, host_port)

# Hidden test

class NormalResultTest(SwitchMLTest):
    # Normal process for get result
    def runTest(self):
        mac_addresses = ['08:00:00:00:01:11', '08:00:00:00:02:22', '08:00:00:00:03:33', '08:00:00:00:04:44']
        ip_addresses = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        ports = [1, 2, 3, 4]

        gradients = [
            (1, 2, 3, 4, 5, 6, 7, 8), 
            (1, 2, 3, 4, 5, 6, 7, 8), 
            (1, 2, 3, 4, 5, 6, 7, 8), 
            (1, 2, 3, 4, 5, 6, 7, 8)
        ]
        result = (4, 8, 12, 16, 20, 24, 28, 32)

        # one by one, send the gradients to the switch
        for i in range(0, 4):
            host_mac = mac_addresses[i]
            host_ip = ip_addresses[i]
            host_port = ports[i]
            host_id = get_host_id(host_ip)
            # print("HostID of ", host_ip, " is ", host_id)
            host_op_code = 0x0101
            data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradients[i]

            # data packet
            pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
            pkt = pkt / IP(src=host_ip, dst="10.0.0.254") 
            pkt = pkt / UDP(dport=0x3824, sport=0x3824, chksum=0) 
            pkt = pkt / SWITCHML(
                hostID=host_id, opCode=host_op_code, 
                val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
                val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)
            
            tu.send_packet(self, host_port, pkt)
            
            # expected status packet, unless is the last one
            # the last one will directly get the result
            if i != 3:
                success_code = 0xFFFF
                exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
                exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
                exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
                exp_pkt = exp_pkt / SWITCHML(
                    hostID=host_id, opCode=success_code, 
                    val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
                    val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)
            
                tu.verify_packet(self, exp_pkt, host_port)
        
        # one by one, get the result from the switch
        for i in range(0, 4):
            result_pkt = Ether(src="08:00:00:00:FF:FF", dst=mac_addresses[i], type=0x800)
            result_pkt = result_pkt / IP(src="10.0.0.254", dst=ip_addresses[i])
            result_pkt = result_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
            result_pkt = result_pkt / SWITCHML(
                hostID=get_host_id(ip_addresses[i]), opCode=0x1234, 
                val0 = result[0], val1 = result[1], val2 = result[2], val3 = result[3], 
                val4 = result[4], val5 = result[5], val6 = result[6], val7 = result[7])
            tu.verify_packet(self, result_pkt, ports[i])
        
class MultipleRoundsTest(SwitchMLTest):
    # Normal process for get result
    def runTest(self):
        mac_addresses = ['08:00:00:00:01:11', '08:00:00:00:02:22', '08:00:00:00:03:33', '08:00:00:00:04:44']
        ip_addresses = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        ports = [1, 2, 3, 4]

        for _ in range(0, 10): # 10 rounds
            # randomly generate gradients
            gradients = [ (random.randint(0, 100), random.randint(0, 100), random.randint(0, 100), random.randint(0, 100),
                           random.randint(0, 100), random.randint(0, 100), random.randint(0, 100), random.randint(0, 100)) for _ in range(0, 4)]
            result = tuple([sum(x) for x in zip(*gradients)])

            # one by one, send the gradients to the switch
            for i in range(0, 4):
                host_mac = mac_addresses[i]
                host_ip = ip_addresses[i]
                host_port = ports[i]
                host_id = get_host_id(host_ip)
                # print("HostID of ", host_ip, " is ", host_id)
                host_op_code = 0x0101
                data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradients[i]

                # data packet
                pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
                pkt = pkt / IP(src=host_ip, dst="10.0.0.254") 
                pkt = pkt / UDP(dport=0x3824, sport=0x3824, chksum=0) 
                pkt = pkt / SWITCHML(
                    hostID=host_id, opCode=host_op_code, 
                    val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
                    val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)
                
                tu.send_packet(self, host_port, pkt)
                
                # expected status packet, unless is the last one
                # the last one will directly get the result
                if i != 3:
                    success_code = 0xFFFF
                    exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
                    exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
                    exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
                    exp_pkt = exp_pkt / SWITCHML(
                        hostID=host_id, opCode=success_code, 
                        val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
                        val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)
                
                    tu.verify_packet(self, exp_pkt, host_port)
            
            # one by one, get the result from the switch
            for i in range(0, 4):
                result_pkt = Ether(src="08:00:00:00:FF:FF", dst=mac_addresses[i], type=0x800)
                result_pkt = result_pkt / IP(src="10.0.0.254", dst=ip_addresses[i])
                result_pkt = result_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
                result_pkt = result_pkt / SWITCHML(
                    hostID=get_host_id(ip_addresses[i]), opCode=0x1234, 
                    val0 = result[0], val1 = result[1], val2 = result[2], val3 = result[3], 
                    val4 = result[4], val5 = result[5], val6 = result[6], val7 = result[7])
                tu.verify_packet(self, result_pkt, ports[i])

# Hidden test

class WrongSwitchIPTest(SwitchMLTest):
    # Host sends to wrong SwitchML IP
    def runTest(self):
        gradient = (1, 2, 3, 4, 5, 6, 7, 8)
        host_mac = '08:00:00:00:01:11'
        host_ip = '10.0.0.1'
        host_port = 1
        host_id = get_host_id(host_ip)
        host_op_code = 0x0101
        data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradient

        # data packet
        pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
        pkt = pkt / IP(src=host_ip, dst="192.168.1.1") 
        pkt = pkt / UDP(dport=0x3824, sport=0x3824, chksum=0) 
        pkt = pkt / SWITCHML(
            hostID=host_id, opCode=host_op_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.send_packet(self, host_port, pkt)
        tu.verify_packet(self, pkt, 1)
        tu.verify_packet(self, pkt, 2)
        tu.verify_packet(self, pkt, 3)
        tu.verify_packet(self, pkt, 4)


class WrongUDPPortTest(SwitchMLTest):
    # Host using wrong UDP IP
    def runTest(self):
        gradient = (1, 2, 3, 4, 5, 6, 7, 8)
        host_mac = '08:00:00:00:01:11'
        host_ip = '10.0.0.1'
        host_port = 1
        host_id = get_host_id(host_ip)
        host_op_code = 0x0101
        data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradient

        # data packet
        pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
        pkt = pkt / IP(src=host_ip, dst="10.0.0.254") 
        pkt = pkt / UDP(dport=0x3927, sport=0x3927, chksum=0) 
        pkt = pkt / SWITCHML(
            hostID=host_id, opCode=host_op_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.send_packet(self, host_port, pkt)

        # verify the packet is not forwarded
        tu.verify_no_packet(self, pkt, 1) 
        tu.verify_no_packet(self, pkt, 2) 
        tu.verify_no_packet(self, pkt, 3) 
        tu.verify_no_packet(self, pkt, 4) 

        failure_code = 0x0000
        exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
        exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
        exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
        exp_pkt = exp_pkt / SWITCHML(
            hostID=host_id, opCode=failure_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.verify_no_packet(self, exp_pkt, host_port)

        success_code = 0xFFFF
        exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
        exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
        exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
        exp_pkt = exp_pkt / SWITCHML(
            hostID=host_id, opCode=success_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.verify_no_packet(self, exp_pkt, host_port)
        # the packet should be dropped 
        # because the UDP port is wrong, then it shouldn't be recognized as SwitchML packet
        # and switchML won't process it because SwitchML is not running at the wrong port
        # also the forwarding table won't match the packet, so it will be dropped

class WrongProtocolTest(SwitchMLTest):
    # SwitchML packet wrapped in TCP packets
    def runTest(self):
        gradient = (1, 2, 3, 4, 5, 6, 7, 8)
        host_mac = '08:00:00:00:01:11'
        host_ip = '10.0.0.1'
        host_port = 1
        host_id = get_host_id(host_ip)
        host_op_code = 0x0101
        data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradient

        # data packet
        pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
        pkt = pkt / IP(src=host_ip, dst="10.0.0.254") 
        pkt = pkt / TCP(dport=0x3824, sport=0x3824, chksum=0) 
        pkt = pkt / SWITCHML(
            hostID=host_id, opCode=host_op_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.send_packet(self, host_port, pkt)
        
        # verify the packet is not forwarded
        tu.verify_no_packet(self, pkt, 1) 
        tu.verify_no_packet(self, pkt, 2) 
        tu.verify_no_packet(self, pkt, 3) 
        tu.verify_no_packet(self, pkt, 4)

        failure_code = 0x0000
        exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
        exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
        exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
        exp_pkt = exp_pkt / SWITCHML(
            hostID=host_id, opCode=failure_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.verify_no_packet(self, exp_pkt, host_port)

        success_code = 0xFFFF
        exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
        exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
        exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
        exp_pkt = exp_pkt / SWITCHML(
            hostID=host_id, opCode=success_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.verify_no_packet(self, exp_pkt, host_port)

# # class DamagedPacketTest(SwitchMLTest):
#     # SwitchML packet with damage
#     # Might be too much for this assignment, don't do damage detection

class WrongOpCodeTest(SwitchMLTest):
    # Received unexpected Operation code
    def runTest(self):
        gradient = (1, 2, 3, 4, 5, 6, 7, 8)
        host_mac = '08:00:00:00:01:11'
        host_ip = '10.0.0.1'
        host_port = 1
        host_id = get_host_id(host_ip)
        wrong_op_code = 0xFFFF
        data_val0, data_val1, data_val2, data_val3, data_val4, data_val5, data_val6, data_val7 = gradient

        # data packet
        pkt =  Ether(src=host_mac, dst="08:00:00:00:FF:FF", type=0x800)
        pkt = pkt / IP(src=host_ip, dst="10.0.0.254") 
        pkt = pkt / UDP(dport=0x3824, sport=0x3824, chksum=0) 
        pkt = pkt / SWITCHML(
            hostID=host_id, opCode=wrong_op_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.send_packet(self, host_port, pkt)

        failure_code = 0x0000
        exp_pkt = Ether(src="08:00:00:00:FF:FF", dst=host_mac, type=0x800)
        exp_pkt = exp_pkt / IP(src="10.0.0.254", dst=host_ip)
        exp_pkt = exp_pkt / UDP(dport=0x3824, sport=0x3824, chksum=0)
        exp_pkt = exp_pkt / SWITCHML(
            hostID=host_id, opCode=failure_code, 
            val0 = data_val0, val1 = data_val1, val2 = data_val2, val3 = data_val3, 
            val4 = data_val4, val5 = data_val5, val6 = data_val6, val7 = data_val7)

        tu.verify_packet(self, exp_pkt, host_port)

# class UnmatchHostIDTest(SwitchMLTest):
#     # Received HostID and IP addr not match
#     # Ignore this situation, a real proper setup won't cause this.