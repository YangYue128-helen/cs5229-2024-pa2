/* -*- P4_16 -*- */

// CS5229 Programming Assignment 2
// Part B - Switch ML
//
// Name: Yang Yue
// Student Number: A0194569J
// NetID: e0376999

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  IPV4_UDP_PRON = 0x11;
const bit<16> SWITCHML_UDP_PORT = 0x3824;
const bit<32> SWITCH_ML_CAPACITY = 8;
const bit<32> SWITCH_ML_HOST_NUM = 4;

const bit<32> SWITCH_IP = 0x0a0000FE;

enum bit<16> SWITCHML_OPT {
    DROPOFF = 0x0101,
    RECORDED = 0xFFFF,
    FAILURE = 0x0000,
    RESULT = 0x1234
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    /* TODO: your code here */
    /* Hint: define ICMP header */
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
}

header udp_t {
    /* TODO: your code here */
    /* Hint: define UDP header */
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header switchml_t {
    /* TODO: your code here */
    /* Hint: define SwitchML header */
    bit<16> workerID;
    bit<16> opCode;
    bit<32> value0;
    bit<32> value1;
    bit<32> value2;
    bit<32> value3;
    bit<32> value4;
    bit<32> value5;
    bit<32> value6;
    bit<32> value7;
}

struct metadata {
    /* Do you need any meta data? */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    switchml_t   switch_ml;
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
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;  
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_UDP_PRON: parse_udp;
            default: accept;  
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            SWITCHML_UDP_PORT: parse_switchml;
            default: accept;  
        }
    }

    state parse_switchml {
        packet.extract(hdr.switch_ml);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* TODO: Define your registers */
    register<bit<32>>(SWITCH_ML_CAPACITY) gradient_sum;
    register<bit<1>>(SWITCH_ML_HOST_NUM) worker_recorded;
    register<bit<32>>(1) workers_done;
    /* TODO: Define your action functions */


    action ipv4_forward_action(egressSpec_t port) {
        /* TODO: your code here */
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }
    
    action multicast() {
        standard_metadata.mcast_grp = 1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward_action;
            multicast;
            drop;
        }
        default_action = multicast();
    }

    apply {
        if (hdr.ethernet.isValid() && hdr.ipv4.isValid()) {
            if (hdr.ipv4.dstAddr == SWITCH_IP ) {
                if (hdr.udp.isValid() && hdr.udp.dstPort == SWITCHML_UDP_PORT) {
                    if (hdr.switch_ml.isValid()) {
                        if (hdr.switch_ml.opCode == (bit<16>)SWITCHML_OPT.DROPOFF) {
                            bit<1> already_recorded;
                            worker_recorded.read(already_recorded, (bit<32>)hdr.switch_ml.workerID - 1);

                            if (already_recorded == 0) {
                                bit<32> sum_tmp;
                                gradient_sum.read(sum_tmp, 0);
                                sum_tmp = sum_tmp + hdr.switch_ml.value0;
                                gradient_sum.write(0, sum_tmp);

                                gradient_sum.read(sum_tmp, 1);
                                sum_tmp = sum_tmp + hdr.switch_ml.value1;
                                gradient_sum.write(1, sum_tmp);

                                gradient_sum.read(sum_tmp, 2);
                                sum_tmp = sum_tmp + hdr.switch_ml.value2;
                                gradient_sum.write(2, sum_tmp);

                                gradient_sum.read(sum_tmp, 3);
                                sum_tmp = sum_tmp + hdr.switch_ml.value3;
                                gradient_sum.write(3, sum_tmp);

                                gradient_sum.read(sum_tmp, 4);
                                sum_tmp = sum_tmp + hdr.switch_ml.value4;
                                gradient_sum.write(4, sum_tmp);

                                gradient_sum.read(sum_tmp, 5);
                                sum_tmp = sum_tmp + hdr.switch_ml.value5;
                                gradient_sum.write(5, sum_tmp);

                                gradient_sum.read(sum_tmp, 6);
                                sum_tmp = sum_tmp + hdr.switch_ml.value6;
                                gradient_sum.write(6, sum_tmp);

                                gradient_sum.read(sum_tmp, 7);
                                sum_tmp = sum_tmp + hdr.switch_ml.value7;
                                gradient_sum.write(7, sum_tmp);
                                
                                worker_recorded.write((bit<32>)hdr.switch_ml.workerID - 1, 1);
                                bit<32> done_count;
                                workers_done.read(done_count, 0);
                                done_count = done_count + 1;
                                workers_done.write(0, done_count);
                            }

                            hdr.switch_ml.opCode = (bit<16>)SWITCHML_OPT.RECORDED;
                            standard_metadata.egress_spec = standard_metadata.ingress_port;

                            //if all workders done, multicast
                            bit<32> total_workers_done;
                            workers_done.read(total_workers_done, 0);
                            if (total_workers_done == SWITCH_ML_HOST_NUM) {
                                hdr.switch_ml.opCode = (bit<16>)SWITCHML_OPT.RESULT;
                                gradient_sum.read(hdr.switch_ml.value0, 0);
                                gradient_sum.read(hdr.switch_ml.value1, 1);
                                gradient_sum.read(hdr.switch_ml.value2, 2);
                                gradient_sum.read(hdr.switch_ml.value3, 3);
                                gradient_sum.read(hdr.switch_ml.value4, 4);
                                gradient_sum.read(hdr.switch_ml.value5, 5);
                                gradient_sum.read(hdr.switch_ml.value6, 6);
                                gradient_sum.read(hdr.switch_ml.value7, 7);
                                multicast();
                                //reset
                                gradient_sum.write(0, 0);
                                gradient_sum.write(1, 0);
                                gradient_sum.write(2, 0);
                                gradient_sum.write(3, 0);
                                gradient_sum.write(4, 0);
                                gradient_sum.write(5, 0);
                                gradient_sum.write(6, 0);
                                gradient_sum.write(7, 0);
                                worker_recorded.write(0, 0);
                                worker_recorded.write(1, 0);
                                worker_recorded.write(2, 0);
                                worker_recorded.write(3, 0);
                                workers_done.write(0, 0);
                            }
                        } else {
                            // invalid opcode
                            hdr.switch_ml.opCode = (bit<16>)SWITCHML_OPT.FAILURE;
                            standard_metadata.egress_spec = standard_metadata.ingress_port;
                            
                            macAddr_t tmp = hdr.ethernet.srcAddr;
                            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                            hdr.ethernet.dstAddr = tmp;

                            ip4Addr_t tmp2 = hdr.ipv4.srcAddr;
                            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                            hdr.ipv4.dstAddr = tmp2;

                            bit<16> tmp3 = hdr.udp.srcPort;
                            hdr.udp.srcPort = hdr.udp.dstPort;
                            hdr.udp.dstPort = tmp3;
                        }
                    } else {
                        //invalid switch_ml
                        hdr.switch_ml.opCode = (bit<16>)SWITCHML_OPT.FAILURE;
                        standard_metadata.egress_spec = standard_metadata.ingress_port;
                        macAddr_t tmp = hdr.ethernet.srcAddr;
                        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                        hdr.ethernet.dstAddr = tmp;

                        ip4Addr_t tmp2 = hdr.ipv4.srcAddr;
                        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                        hdr.ipv4.dstAddr = tmp2;

                        bit<16> tmp3 = hdr.udp.srcPort;
                        hdr.udp.srcPort = hdr.udp.dstPort;
                        hdr.udp.dstPort = tmp3;
                    }
                } else {
                    drop();
                }
                
            } else {
                //normal forwarding
                ipv4_forward.apply();
            } 
        } else {
            // Not IPv4 packet
            drop();
        }
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

    action set_host(macAddr_t eth_addr, ip4Addr_t ip_addr, bit<16> host_id) {
        /* TODO: your code here */
        hdr.ethernet.dstAddr = eth_addr;
        hdr.ipv4.dstAddr = ip_addr;
        hdr.switch_ml.workerID = host_id;
    }

    table port_to_host {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            set_host;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        /* TODO: your codes here */
        /* HINT: update destination information */
        /* HINT: check the runtime table, there will something you need*/
        if (standard_metadata.mcast_grp == 1) {
            port_to_host.apply();
        }
       
        
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: your code here */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.switch_ml);
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
