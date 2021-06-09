/* -*- P4_16 -*- */
//Copyright (c) 2019 Belma Turkovic (b.turkovic-2@tudelft.nl)
//TU Delft Embedded and Networked Systems Group.

#include <core.p4>
#include <v1model.p4>
const bit<9> DROP_PORT = 511;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_ARP = 0x0806;
const bit<16> ETHERTYPE_LLDP1 = 0x88CC;
const bit<16> ETHERTYPE_LLDP2 = 0x88CD;
const bit<16> CPU_PORT = 0x40;
const bit<16> CPU_REASON_NO_ARP_ENTRY = 0x0000;
const bit<16> CPU_REASON_ARP_MSG = 0x0001;
const bit<16> CPU_REASON_DATA_MSG = 0x0002;
const bit<16> CPU_REASON_LLDP_MSG = 0x0003;
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

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
    bit<8>    tos;
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

//packets used by the controller to do topology detection as 
//well as link latency measurments by sending periodic packets from/to the controller
header lldp_t {
    bit<16> dev_id;
    bit<64> delay_ingress;
    bit<32> deq_timedelta;
    bit<32> deq_qdepth;
    bit<32> enq_qdepth;
    bit<16> port;
}

//additional header added to the packet before being sent to the controller
header cpu_header_t {
    bit<64> zeros;
    bit<16> reason;
    bit<16> source_ingress;
    bit<16> port;
    bit<16> dev_id;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    bit<48> hwSrcAddr;
    bit<32> protoSrcAddr;
    bit<48> hwDstAddr;
    bit<32> protoDstAddr;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<8> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
    bit<8> resubmit_flag;
    bit<8> recirculate_flag;
    bit<3> priority;
}

struct metadata {
    bit<16> switch_processed;
    bit<32> nhop_ipv4;
    bit<1> found;
    bit<1> cloned;
    bit<64> ingress_delay;
    bit<32> queue_delay;
    bit<16> type;
    bit<32> deqdepth;
    bit<32> enqdepth;
    bit<1>  slice_change;
    bit<1>  ingress;
    bit<6>  sliceID;
    bit<16> ingress_switch;
    bit<9> currentPort;
    bit<1> tactileFlow;
    bit<8> flow_hash;
    bit<1> egressSwitch;
    bit<16> flowid;
    bool send_mac_learn_msg;
    intrinsic_metadata_t intrinsic_metadata;
}


struct headers {
    cpu_header_t cpu_header;
    ethernet_t   ethernet;
    arp_t        arp;
    lldp_t       lldp;
    lldp_t       lldp2;
    ipv4_t       ipv4;
    }



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(packet.lookahead<bit<64>>()) {
            0: parse_cpu_header;
            default: parse_ethernet;
        }
    }

    state parse_cpu_header {
        packet.extract(hdr.cpu_header);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_LLDP2 : parse_lldp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_lldp {
        packet.extract(hdr.lldp);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ethernet.etherType) {
            default: accept;
        }
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

    action drop_packet() {
        standard_metadata.egress_spec = DROP_PORT;
    }

    action no_action() {}
    
    action do_send_to_cpu(bit<16> reason, bit<16> cpu_port) {
        hdr.cpu_header.setValid();
        hdr.cpu_header.reason = reason;
        hdr.cpu_header.source_ingress = meta.ingress_switch;
        hdr.cpu_header.port = (bit<16>)standard_metadata.ingress_port;
        standard_metadata.egress_spec = cpu_port[8:0];
    }


    action lldp_to_cpu(bit<16> reason, bit<16> cpu_port) {
        hdr.cpu_header.setValid();
        meta.switch_processed = 0x0001;
        hdr.cpu_header.reason = reason;
        hdr.cpu_header.port = (bit<16>)standard_metadata.ingress_port;
        standard_metadata.egress_spec = cpu_port[8:0];
    }

    action set_nhop(bit<32> nxtHop, bit<16> port) {
        standard_metadata.egress_spec = port[8:0];
        meta.nhop_ipv4 = nxtHop;
        meta.found = 1;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_dmac(macAddr_t dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    action do_decap_lldp_cpu() {
        hdr.lldp.setValid();
        standard_metadata.egress_spec = hdr.cpu_header.port[8:0];
        meta.switch_processed = hdr.cpu_header.dev_id;
        hdr.cpu_header.setInvalid();
    }

    action do_decap_cpu_header() {
        standard_metadata.egress_spec = hdr.cpu_header.port[8:0];
        meta.ingress_switch = hdr.cpu_header.source_ingress;
        hdr.cpu_header.setInvalid();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
	    hdr.ipv4.tos: exact;
        }
        actions = {
            set_nhop;
            do_send_to_cpu;
            drop_packet;
            NoAction;
        }
        size = 1024;
        default_action = do_send_to_cpu(CPU_REASON_DATA_MSG, CPU_PORT);
    }


    table forward {
        key = {
            meta.nhop_ipv4 : exact;
        }
        actions = {
            set_dmac;
            do_send_to_cpu;
            drop_packet;
        }
        size = 512;
        default_action = do_send_to_cpu(CPU_REASON_NO_ARP_ENTRY, CPU_PORT);
    }

    table decap_cpu_header {
        key = {
            hdr.cpu_header.reason : exact;
        }
        actions = {
            do_decap_cpu_header;
            do_decap_lldp_cpu;
        }
        default_action = do_decap_cpu_header();
        size = 1;
    }


    apply {

        if (hdr.cpu_header.isValid()) decap_cpu_header.apply();
        else {
            if (hdr.arp.isValid()) do_send_to_cpu(CPU_REASON_ARP_MSG, CPU_PORT);
            if (hdr.lldp.isValid()) lldp_to_cpu(CPU_REASON_LLDP_MSG, CPU_PORT);
	}

	if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply(); 
	    if (meta.found == 1) forward.apply();
        }
         
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    

    action _drop() {
        mark_to_drop();
    }

    action rewrite_mac(macAddr_t smac) {
        hdr.ethernet.srcAddr = smac;
    }


    action set_lldp1() {
        hdr.lldp.dev_id = meta.switch_processed;
        hdr.lldp.delay_ingress = (bit<64>)standard_metadata.enq_timestamp-(bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.lldp.deq_timedelta = standard_metadata.deq_timedelta;
        hdr.lldp.enq_qdepth = (bit<32>)standard_metadata.enq_qdepth;
        hdr.lldp.deq_qdepth = (bit<32>)standard_metadata.deq_qdepth;
        hdr.lldp.port = (bit<16>)standard_metadata.egress_port;
        hdr.ethernet.etherType = ETHERTYPE_LLDP2;
    }

    action set_lldp2() {
        hdr.lldp2.delay_ingress = (bit<64>)standard_metadata.enq_timestamp-(bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.lldp2.deq_timedelta = standard_metadata.deq_timedelta;
        hdr.lldp2.enq_qdepth = (bit<32>)standard_metadata.enq_qdepth;
        hdr.lldp2.deq_qdepth = (bit<32>)standard_metadata.deq_qdepth;
        hdr.lldp2.port = (bit<16>)standard_metadata.ingress_port;
    }

    table send_frame {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_mac;
            _drop;
        }
        default_action = _drop();
        size = 256;
    }
         

    apply { 

        if (hdr.cpu_header.isValid() && hdr.lldp.isValid()) {
            hdr.lldp2.setValid();
            set_lldp2();
        } else if (hdr.lldp.isValid()) set_lldp1();
          
        if (!hdr.cpu_header.isValid()) send_frame.apply();
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(true,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.cpu_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.lldp);
        packet.emit(hdr.lldp2);
        packet.emit(hdr.ipv4);
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

