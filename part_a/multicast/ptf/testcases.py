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

from scapy.all import *

class MulticastPkt(Packet):
    name = "multicast"
    fields_desc = [
        BitField("mcast_grp", 0x0000, 16)
    ]
bind_layers(Ether, MulticastPkt, type=0x1234)

class MulticastTest(BaseTest):

    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        logging.debug("MulticastTest.setUp()")
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
        # te = sh.TableEntry('icmp_filter_table')(action='drop')
        # te.match['hdr.ipv4.dstAddr'] = "33.33.33.33"
        # te.insert()
        te = sh.TableEntry('mac_lookup')(action='mac_forward')
        te.match['hdr.ethernet.dstAddr'] = "08:00:00:00:01:11"
        te.action['port'] = "1"
        te.insert()
        te = sh.TableEntry('mac_lookup')(action='mac_forward')
        te.match['hdr.ethernet.dstAddr'] = "08:00:00:00:02:22"
        te.action['port'] = "2"
        te.insert()
        te = sh.TableEntry('mac_lookup')(action='mac_forward')
        te.match['hdr.ethernet.dstAddr'] = "08:00:00:00:03:33"
        te.action['port'] = "3"
        te.insert()

        te = sh.TableEntry('port_to_mac')(action='set_mac_dst_addr')
        te.match['standard_metadata.egress_port'] = "1"
        te.action['addr'] = "08:00:00:00:01:11"
        te.insert()
        te = sh.TableEntry('port_to_mac')(action='set_mac_dst_addr')
        te.match['standard_metadata.egress_port'] = "2"
        te.action['addr'] = "08:00:00:00:02:22"
        te.insert()
        te = sh.TableEntry('port_to_mac')(action='set_mac_dst_addr')
        te.match['standard_metadata.egress_port'] = "3"
        te.action['addr'] = "08:00:00:00:03:33"
        te.insert()

        te = sh.MulticastGroupEntry(1)
        te.add(1, 1).add(2, 1).add(3, 1)
        te.insert()

        te = sh.MulticastGroupEntry(12)
        te.add(1, 1).add(2, 1)
        te.insert()
        
        te = sh.MulticastGroupEntry(13)
        te.add(1, 1).add(3, 1)
        te.insert()
        
        te = sh.MulticastGroupEntry(23)
        te.add(2, 1).add(3, 1)
        te.insert()

    def tearDown(self):
        logging.debug("MulticastTest.tearDown()")
        sh.teardown()

class NormalTrafficTest1(MulticastTest): # Raw Ethernet Pkts
    def runTest(self):
        macAddresses = ['08:00:00:00:01:11', '08:00:00:00:02:22', '08:00:00:00:03:33']

        for src_address in macAddresses:
            for dst_address in macAddresses:
                if src_address != dst_address:
                    pkt = Ether(src=src_address, dst=dst_address, type=0x0000)
                    pkt = pkt / Raw(load="So call it what you want, yeah, call it what you want to")
                    tu.send_packet(self, macAddresses.index(src_address) + 1, pkt)

                    exp_pkt = Ether(src=src_address, dst=dst_address, type=0x0000)
                    exp_pkt = exp_pkt / Raw(load="So call it what you want, yeah, call it what you want to")
                    tu.verify_packets(self, exp_pkt, [macAddresses.index(dst_address) + 1])

class NormalTrafficTest2(MulticastTest): # Common IPv4 Pkts
    def runTest(self):
        IPAddresses = [('08:00:00:00:01:11', '10.0.0.1'), ('08:00:00:00:02:22', '10.0.0.2'), ('08:00:00:00:03:33', '10.0.0.3')]

        for src_address in IPAddresses:
            for dst_address in IPAddresses:
                if src_address[0] != dst_address[0]:
                    pkt = Ether(src=src_address[0], dst=dst_address[0], type = 0x0800) 
                    pkt = pkt / IP(src=src_address[1], dst=dst_address[1]) / Raw(load="Devils roll the dice, angels roll their eyes")
                    tu.send_packet(self, IPAddresses.index(src_address) + 1, pkt)

                    exp_pkt = Ether(src=src_address[0], dst=dst_address[0], type = 0x0800) 
                    exp_pkt = exp_pkt /IP(src=src_address[1], dst=dst_address[1]) / Raw(load="Devils roll the dice, angels roll their eyes")
                    tu.verify_packets(self, exp_pkt, [IPAddresses.index(dst_address) + 1])

class NormalTrafficTest3(MulticastTest): # Common TCP Pkts
    def runTest(self):
        IPAddresses = [('08:00:00:00:01:11', '10.0.0.1'), ('08:00:00:00:02:22', '10.0.0.2'), ('08:00:00:00:03:33', '10.0.0.3')]

        for src_address in IPAddresses:
            for dst_address in IPAddresses:
                if src_address[0] != dst_address[0]:
                    pkt = tu.simple_tcp_packet(eth_src=src_address[0], eth_dst=dst_address[0], ip_src=src_address[1], ip_dst=dst_address[1])
                    tu.send_packet(self, IPAddresses.index(src_address) + 1, pkt)
                    tu.verify_packets(self, pkt, [IPAddresses.index(dst_address) + 1])

class NormalTrafficTest4(MulticastTest): # Common UDP Pkts
    def runTest(self):
        IPAddresses = [('08:00:00:00:01:11', '10.0.0.1'), ('08:00:00:00:02:22', '10.0.0.2'), ('08:00:00:00:03:33', '10.0.0.3')]

        for src_address in IPAddresses:
            for dst_address in IPAddresses:
                if src_address[0] != dst_address[0]:
                    pkt = tu.simple_udp_packet(
                        eth_src=src_address[0], eth_dst=dst_address[0],
                        ip_src=src_address[1], ip_dst=dst_address[1]
                    )
                    tu.send_packet(self, IPAddresses.index(src_address) + 1, pkt)
                    tu.verify_packets(self, pkt, [IPAddresses.index(dst_address) + 1])

class NormalTrafficTest5(MulticastTest): # ARP discovery function
    def runTest(self):
        pkt = tu.simple_arp_packet(eth_src="08:00:00:00:01:11", hw_snd="08:00:00:00:01:11", ip_snd="10.0.0.1", ip_tgt="10.0.0.2")
        tu.send_packet(self, 1, pkt)
        tu.verify_packet(self, pkt, 1)
        tu.verify_packet(self, pkt, 2)
        tu.verify_packet(self, pkt, 3)

class UnknownMacTest(MulticastTest):
    def runTest(self):
        pkt = Ether(src = "08:00:00:00:01:11", dst = "08:00:00:00:04:44") / Raw(load="I don't regret it one bit, 'cause he had it coming")
        tu.send_packet(self, 1, pkt)

        exp_pkt = Ether(src = "08:00:00:00:01:11", dst = "08:00:00:00:04:44") / Raw(load="I don't regret it one bit, 'cause he had it coming")
        tu.verify_packet(self, exp_pkt, 1)
        tu.verify_packet(self, exp_pkt, 2)
        tu.verify_packet(self, exp_pkt, 3)

class SelfTrafficTest(MulticastTest):
    def runTest(self):
        pkt = Ether(src = "08:00:00:00:01:11", dst = "08:00:00:00:01:11") / Raw(load="Another fortnight lost in America")
        tu.send_packet(self, 1, pkt)

        exp_pkt = Ether(src = "08:00:00:00:01:11", dst = "08:00:00:00:01:11") / Raw(load="Another fortnight lost in America")
        tu.verify_packet(self, exp_pkt, 1)

class UnicastTest(MulticastTest):
    def runTest(self):
        macAddresses = ['08:00:00:00:01:11', '08:00:00:00:02:22', '08:00:00:00:03:33']
        for src_address in macAddresses:
            for dst_address in macAddresses:
                if src_address != dst_address:
                    pkt = Ether(src=src_address, dst=dst_address, type=0x1234)
                    pkt = pkt / MulticastPkt(mcast_grp=0) / Raw(load='So casually cruel in the name of being honest')
                    tu.send_packet(self, macAddresses.index(src_address) + 1, pkt)

                    exp_pkt = Ether(src=src_address, dst=dst_address, type=0x1234)
                    exp_pkt = exp_pkt / MulticastPkt(mcast_grp=0) / Raw(load='So casually cruel in the name of being honest')
                    tu.verify_packets(self, exp_pkt, [macAddresses.index(dst_address) + 1])


class MulticastTest1(MulticastTest):
    def runTest(self):
        pkt = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:02:22', type=0x1234)
        pkt = pkt / MulticastPkt(mcast_grp=23) / Raw(load='Except on midnights like this')
        tu.send_packet(self, 1, pkt)

        exp_pkt1 = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:02:22', type=0x1234)
        exp_pkt1 = exp_pkt1 / MulticastPkt(mcast_grp=23) / Raw(load='Except on midnights like this')
        tu.verify_packet(self, exp_pkt1, 2)
        exp_pkt2 = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:03:33', type=0x1234)
        exp_pkt2 = exp_pkt2 / MulticastPkt(mcast_grp=23) / Raw(load='Except on midnights like this')
        tu.verify_packet(self, exp_pkt2, 3)
        unexp_pkt = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:01:11', type=0x1234)
        unexp_pkt = unexp_pkt / MulticastPkt(mcast_grp=23) / Raw(load='Except on midnights like this')
        tu.verify_no_packet(self, unexp_pkt, 1)

class MulticastTest2(MulticastTest):
    def runTest(self):
        macAddresses = [
            (1, '08:00:00:00:01:11', 23, 2, '08:00:00:00:02:22', 3, '08:00:00:00:03:33'), 
            (2, '08:00:00:00:02:22', 13, 1, '08:00:00:00:01:11', 3, '08:00:00:00:03:33'), 
            (3, '08:00:00:00:03:33', 12, 1, '08:00:00:00:01:11', 2, '08:00:00:00:02:22')
        ]
        for src_port, src_address, group, dst1_port, dst1_mac, dst2_port, dst2_mac in macAddresses:
            pkt = Ether(src=src_address, dst=dst1_mac, type=0x1234)
            pkt = pkt / MulticastPkt(mcast_grp=group) / Raw(load='August sipped away like a bottle of wine')
            tu.send_packet(self, src_port, pkt)

            exp_pkt1 = Ether(src=src_address, dst=dst1_mac, type=0x1234)
            exp_pkt1 = exp_pkt1 / MulticastPkt(mcast_grp=group) / Raw(load='August sipped away like a bottle of wine')
            tu.verify_packet(self, exp_pkt1, dst1_port)
            exp_pkt2 = Ether(src=src_address, dst=dst2_mac, type=0x1234)
            exp_pkt2 = exp_pkt2 / MulticastPkt(mcast_grp=group) / Raw(load='August sipped away like a bottle of wine')
            tu.verify_packet(self, exp_pkt2, dst2_port)
            # tu.verify_no_other_packets(self)
            unexp_pkt = Ether(src=src_address, dst=src_address, type=0x1234)
            unexp_pkt = unexp_pkt / MulticastPkt(mcast_grp=group) / Raw(load='August sipped away like a bottle of wine')
            tu.verify_no_packet(self, unexp_pkt, src_port)

class ConfuseTest(MulticastTest):
    def runTest(self):
        pkt = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:02:22', type=0x1234)
        pkt = pkt / MulticastPkt(mcast_grp=23) / MulticastPkt(mcast_grp=0x0000) / Raw(load='Life was a willow and it bent right to your wind')
        tu.send_packet(self, 1, pkt)

        exp_pkt1 = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:02:22', type=0x1234)
        exp_pkt1 = exp_pkt1 / MulticastPkt(mcast_grp=23) / MulticastPkt(mcast_grp=0x0000) / Raw(load='Life was a willow and it bent right to your wind')
        tu.verify_packet(self, exp_pkt1, 2)
        exp_pkt2 = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:03:33', type=0x1234)
        exp_pkt2 = exp_pkt2 / MulticastPkt(mcast_grp=23) / MulticastPkt(mcast_grp=0x0000) / Raw(load='Life was a willow and it bent right to your wind')
        tu.verify_packet(self, exp_pkt2, 3)
        unexp_pkt = Ether(src='08:00:00:00:01:11', dst='08:00:00:00:01:11', type=0x1234)
        unexp_pkt = unexp_pkt / MulticastPkt(mcast_grp=23) / MulticastPkt(mcast_grp=0x0000) / Raw(load='Life was a willow and it bent right to your wind')
        tu.verify_no_packet(self, unexp_pkt, 1)