/* -*- P4_16 -*- */
//Copyright (c) 2019 Belma Turkovic (b.turkovic-2@tudelft.nl)
//TU Delft Embedded and Networked Systems Group.

#include <core.p4>
#include <v1model.p4>
const bit<9> DROP_PORT = 511;
//const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_ARP = 0x0806;
const bit<16> ETHERTYPE_LLDP1 = 0x88CC;
const bit<16> ETHERTYPE_LLDP2 = 0x88CD;
const bit<16> ETHERTYPE_SOURCE = 0xBBBB;
const bit<16> CPU_PORT = 0x40;
const bit<9> LOCAL_CONTROLLER = 0x01;
const bit<16> CPU_REASON_NO_ARP_ENTRY = 0x0000;
const bit<16> CPU_REASON_ARP_MSG = 0x0001;
const bit<16> CPU_REASON_DATA_MSG = 0x0002;
const bit<16> CPU_REASON_LLDP_MSG = 0x0003;
const bit<16> CPU_REASON_TACTILE_ING = 0x0004;
const bit<16> CPU_REASON_TACTILE_EG = 0x0005;
const bit<16> CPU_REASON_SLICE_SW = 0x0007;
const bit<8> REMOVE_SRC = 0xFE;
const bit<64> SRC_HDR = 0xBBBBBBBBBBBBBBBB;
const bit<64> TCT_HDR = 0xDDDDDDDDDDDDDDDD;
#define MAX_TACTILE 256 //max number of tactile flows present at the edge switch
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6



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


header lldp_t {
    bit<16> dev_id;
    bit<64> delay_ingress;
    bit<32> deq_timedelta;
    bit<32> deq_qdepth;
    bit<32> enq_qdepth;
    bit<16> port;
}

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

header slice_conf_t {
    bit<2>      type;
    bit<6>      sliceID;
    bit<8>      length;
    bit<8>      flow_id;
}

header srcRoutes_t {
    bit<128>    ports; //16
}

header srcRoute_t {
    bit<8>      port;
}

header srcRouteAll_t {
    bit<8> port;
}

header ones_t {
    bit<64> ones;
}

struct mac_learn_digest_t {
    bit<9> ingress_port;
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
    bit<16> dev_id;
    bit<16> port;
    bit<32> nhop_ipv4;
    bit<1>  found;
    bit<1>  tactileData;
    bit<8>  last_src;
    bit<16> cloned;
    bit<64> ingress_delay;
    bit<32> queue_delay;
    bit<16> type;
    bit<32> deqdepth;
    bit<32> enqdepth;
    bit<1>  slice_change;
    bit<1>  core;
    bit<8>  sliceID;
    bit<16> ingress_switch;
    bit<16> core_switch;
    bit<9>  prev_Port;
    bit<1>  tactileFlow;
    bit<8>  flow_hash;
    bit<1>  egressSwitch;
    bit<16> flowid;
    intrinsic_metadata_t intrinsic_metadata;
}


struct headers {
    cpu_header_t cpu_header;
    ethernet_t   ethernet;
    arp_t        arp;
    lldp_t       lldp;
    lldp_t       lldp2;
    ipv4_t       ipv4;
    srcRoute_t   srcRoute;
    srcRoutes_t  srcRoutes;   
    slice_conf_t slice_conf;
    ones_t       ones; 
    srcRouteAll_t srcRouteAll;
    }


error {
    IPv4OptionsNotSupported,
    IPv4IncorrectVersion,
    IPv4ChecksumError
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
            //SRC_HDR: parse_srcRouting;  
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
            ETHERTYPE_SOURCE : parse_srcRouting;
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_LLDP2 : parse_lldp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_srcRouting { //fields in source_ingress on mbv2 cannot have variable size.
        packet.extract(hdr.slice_conf);
        packet.extract(hdr.srcRoute);
        transition select(hdr.slice_conf.length){
            1: parse_AllsrcRouting; //parse_ipv4;
            default: accept;
        }
    }

    state parse_AllsrcRouting {
        packet.extract(hdr.srcRoute);
        transition select(packet.lookahead<bit<8>>()){
            REMOVE_SRC: parse_AllsrcRouting;
            default: parse_ipv4;
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

    register<bit<8>>(256) sliceUsedreg;
    register<bit<9>>(256) currentPort;
    register<bit<1>>(256) coreSwitch;
    register<bit<1>>(256) egressSwitch;
    register<bit<1>>(256) tactileFlow;
    register<bit<3>>(256) currentPriority;

    action drop_packet() {
        standard_metadata.egress_spec = DROP_PORT;
    }

    action no_action() {}
    
    action do_send_to_cpu(bit<16> reason, bit<16> cpu_port) {
        hdr.cpu_header.setValid();
        hdr.cpu_header.reason = reason;
        hdr.cpu_header.source_ingress = meta.ingress_switch;
        bit<7> zeros = 0x00;
        hdr.cpu_header.port = zeros ++ standard_metadata.ingress_port;
        standard_metadata.egress_spec = cpu_port[8:0];
    }


    action lldp_to_cpu(bit<16> reason, bit<16> cpu_port) {
        hdr.cpu_header.setValid();
        meta.switch_processed = 0x0001;
        hdr.cpu_header.reason = reason;
        bit<7> zeros = 0x00;
        hdr.cpu_header.port = zeros ++ standard_metadata.ingress_port;
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

    action source_ingress (bit<128> sourceRoute, bit<16> type, bit<16> length, bit<16> port) {
	currentPort.read(meta.prev_Port, (bit<32>)meta.flow_hash);
	meta.port = port;
        hdr.srcRoutes.setValid();
	hdr.cpu_header.setInvalid();
        hdr.slice_conf.setValid();
        hdr.slice_conf.type = type[1:0];
        hdr.slice_conf.sliceID = (bit<6>)hdr.ipv4.tos;
	hdr.slice_conf.flow_id = meta.flow_hash;
        hdr.slice_conf.length = length[7:0];
        hdr.srcRoutes.ports = sourceRoute; //[127:128-2*8];
        standard_metadata.egress_spec = port[8:0];
        hdr.ethernet.etherType = ETHERTYPE_SOURCE;
	sliceUsedreg.write((bit<32>)hdr.slice_conf.flow_id, hdr.ipv4.tos);
	tactileFlow.write((bit<32>)hdr.slice_conf.flow_id, 1);
	currentPort.write((bit<32>)hdr.slice_conf.flow_id, port[8:0]);
	meta.intrinsic_metadata.priority = (bit<3>)hdr.slice_conf.sliceID;
	currentPriority.write((bit<32>)hdr.slice_conf.flow_id, (bit<3>)hdr.slice_conf.sliceID);
    }   

    action srcRoute_nhop() {
        meta.tactileData = 1;
	meta.core_switch = 1;
        hdr.slice_conf.length = hdr.slice_conf.length -1;
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoute.port;
	meta.port = (bit<16>)hdr.srcRoute.port;
	currentPort.write((bit<32>)hdr.slice_conf.flow_id, standard_metadata.egress_spec);
        hdr.srcRoute.setInvalid();
	coreSwitch.write((bit<32>)hdr.slice_conf.flow_id, 1);
	tactileFlow.write((bit<32>)hdr.slice_conf.flow_id, 1);
	meta.intrinsic_metadata.priority = (bit<3>)hdr.slice_conf.sliceID;
	currentPriority.write((bit<32>)hdr.slice_conf.flow_id, (bit<3>)hdr.slice_conf.sliceID);
    }  

    action last_srcRoute_nhop(){
        hdr.slice_conf.setInvalid();
	hdr.srcRoute.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4;
        meta.tactileData=0;
	meta.sliceID=0;
	meta.egressSwitch = 1;
	egressSwitch.write((bit<32>)meta.flow_hash, 1);
    }

    action del_route() {
        meta.core_switch=1;
	meta.tactileFlow=1;
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoute.port;
	meta.port = (bit<16>)hdr.srcRoute.port;
	currentPort.write((bit<32>)hdr.slice_conf.flow_id, 0);
	coreSwitch.write((bit<32>)hdr.slice_conf.flow_id, 0);
	tactileFlow.write((bit<32>)hdr.slice_conf.flow_id, 0);
	currentPriority.write((bit<32>)hdr.slice_conf.flow_id, 0);
    } 

    action forward_tactile () {
	currentPort.read(standard_metadata.egress_spec, (bit<32>)meta.flow_hash); //forward based on the port saved in the registers
	currentPriority.read(meta.intrinsic_metadata.priority, (bit<32>)meta.flow_hash); //set priority based on the value saved in the registers
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
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

    table slice_sw {
        key = {
            hdr.ipv4.dstAddr: lpm;
	    hdr.ipv4.tos: exact;
        }
        actions = {
            source_ingress;
	    no_action;
            do_send_to_cpu;
            drop_packet;
        }
        size = 1024;
        default_action = do_send_to_cpu(CPU_REASON_TACTILE_ING, CPU_PORT);
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

	if (hdr.slice_conf.isValid()) {
		meta.flow_hash = hdr.slice_conf.flow_id;
	} else {
		hash(meta.flow_hash, HashAlgorithm.crc32,10w0,{ hdr.ipv4.dstAddr, hdr.ipv4.srcAddr },10w255);
		tactileFlow.read(meta.tactileFlow, (bit<32>)meta.flow_hash);
	}


        if (hdr.cpu_header.isValid()) decap_cpu_header.apply();
        else {
            if (hdr.arp.isValid()) do_send_to_cpu(CPU_REASON_ARP_MSG, CPU_PORT);
            if (hdr.lldp.isValid()) lldp_to_cpu(CPU_REASON_LLDP_MSG, CPU_PORT);
	}

	egressSwitch.read(meta.egressSwitch, (bit<32>)meta.flow_hash);
        if (hdr.srcRoute.isValid() && hdr.slice_conf.type == 1){ //packet uses slice switching protocol,  core switch
            if (hdr.slice_conf.length != 1) srcRoute_nhop();
            else last_srcRoute_nhop(); //remove slice switching protocol
        } else if (hdr.slice_conf.type == 2) del_route();

	if (hdr.ipv4.isValid() && hdr.ipv4.tos != 0 && meta.core_switch==0 && meta.egressSwitch != 1) { 	//packet needs to use source routing,  edge switch
		coreSwitch.read(meta.core, (bit<32>)meta.flow_hash);
		if (meta.core_switch==0 && meta.core==0){
			sliceUsedreg.read(meta.sliceID, (bit<32>)meta.flow_hash);
			if(meta.sliceID != hdr.ipv4.tos) slice_sw.apply();  //slice was switched 			
			meta.tactileData=1;
		}
	}
	 
	if (hdr.ethernet.isValid() && meta.tactileFlow==0 && meta.tactileData==0 || meta.egressSwitch == 1) { //normal IPv4 flow or the last switch in the tactile flow
	    meta.tactileFlow=0;
	    if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            	ipv4_lpm.apply(); 
		if (meta.found == 1) forward.apply();
	   }
        }

        if (meta.tactileFlow==1 && standard_metadata.egress_spec != 64 && hdr.slice_conf.type == 1) {    //tactile packets without the slice conf protocol
	    	forward_tactile();
        } 
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    register<bit<16>>(1)  devid;
    action _drop() {
        mark_to_drop();
    }

    action rewrite_mac(macAddr_t smac) {
        hdr.ethernet.srcAddr = smac;
    }


    action set_lldp1() {
        hdr.lldp.dev_id = meta.switch_processed;
	devid.write(0, hdr.lldp.dev_id);       
        hdr.lldp.delay_ingress = (bit<64>)standard_metadata.enq_timestamp-(bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.lldp.deq_timedelta = standard_metadata.deq_timedelta;
        hdr.lldp.enq_qdepth = (bit<32>)standard_metadata.enq_qdepth;
        hdr.lldp.deq_qdepth = (bit<32>)standard_metadata.deq_qdepth;
        hdr.lldp.port = (bit<16>)standard_metadata.egress_port;
        hdr.ethernet.etherType = ETHERTYPE_LLDP2;
    }

    action clone_to_local() {	
        clone3<tuple<standard_metadata_t, metadata>>(CloneType.E2E, 1024, { standard_metadata, meta });
    }

    action send_slice_delete() {
        hdr.slice_conf.type = 2;
        hdr.slice_conf.sliceID = (bit<6>)meta.sliceID;
	hdr.slice_conf.flow_id = meta.flow_hash;
	hdr.slice_conf.length = 99;
        clone3<tuple<standard_metadata_t, metadata>>(CloneType.E2E, (bit<32>)meta.prev_Port, { standard_metadata, meta });
	truncate(16);
    }
    
    action set_lldp2() {
        hdr.lldp2.delay_ingress = (bit<64>)standard_metadata.enq_timestamp-(bit<64>)standard_metadata.ingress_global_timestamp;
        hdr.lldp2.deq_timedelta = standard_metadata.deq_timedelta;
        hdr.lldp2.enq_qdepth = (bit<32>)standard_metadata.enq_qdepth;
        hdr.lldp2.deq_qdepth = (bit<32>)standard_metadata.deq_qdepth;
        hdr.lldp2.port = (bit<16>)standard_metadata.ingress_port;
    }

    action manage_bandwidth() {
        hdr.cpu_header.setValid();
	devid.read(meta.dev_id, 0);
        hdr.cpu_header.reason = (bit<16>)hdr.slice_conf.sliceID;
        hdr.cpu_header.dev_id = meta.dev_id;
        hdr.cpu_header.port = meta.port;
        hdr.cpu_header.source_ingress = (bit<16>)hdr.slice_conf.type;
	truncate(16);
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

        if (standard_metadata.instance_type != 0) {
		if (standard_metadata.egress_spec == 1 || standard_metadata.egress_port == 1 ) manage_bandwidth();
	}
        if (hdr.cpu_header.isValid() && hdr.lldp.isValid()) {
            hdr.lldp2.setValid();
            set_lldp2();
        } else if (hdr.lldp.isValid()) set_lldp1();
          
        if (!hdr.cpu_header.isValid() && meta.tactileData!=1) send_frame.apply();
        if (standard_metadata.egress_port != 1 && standard_metadata.egress_spec != 1 && hdr.slice_conf.isValid()) clone_to_local();
        if (standard_metadata.instance_type == 0 && meta.prev_Port != 0 && meta.prev_Port != standard_metadata.egress_port) send_slice_delete(); 
       
    }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
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
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.cpu_header);
        //packet.emit(hdr.ones);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.slice_conf); 
        packet.emit(hdr.srcRoutes);
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

