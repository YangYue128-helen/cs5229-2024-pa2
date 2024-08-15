/* -*- P4_16 -*- */

// CS5229 Programming Assignment 2
// Part A - 1 Multicast
//
// Name: Albert Einstein
// Student Number: A0123456B
// NetID: e0123456

#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<16> ethType_t;

const bit<16> TYPE_MCAST = 0x1234;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    ethType_t   etherType;
}

header multicast_grp_t {
    bit<16> mcast_grp;
    // 0 for unicast,
    // other values for multicast
}

struct metadata {
    bit <1> update_mac;
}

struct headers {
    ethernet_t   ethernet;
    multicast_grp_t multicast_grp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: your code here */
        /* Hint: implement your parser */
        transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { /* Not in use */ }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    action multicast() {
        /* TODO: Your code here */
    }

    action mac_forward(egressSpec_t port) {
        /*  TODO: your code here */
    }

    table mac_lookup {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            broadcast;
            mac_forward;
            drop;
        }
        size = 1024;
        default_action = broadcast;
    }

    apply {

        /*  TODO: your code here */
        /*  HINT: do you need any metadata? */

        mac_lookup.apply();

    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_mac_dst_addr(macAddr_t addr) {
        /* TODO: your code here */
        /* HINT: update MAC address */
    }

    table port_to_mac {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            set_mac_dst_addr;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        /* TODO: your code here */

        port_to_mac.apply();
        
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply { /* Not in use */ }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: your code here */
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
