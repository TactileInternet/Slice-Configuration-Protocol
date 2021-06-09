/* Copyright 2019 Belma Turkovic
* TU Delft Embedded and Networked Systems Group.
*
* NOTICE: THIS FILE IS BASED ON https://github.com/p4lang/PI/tree/master/proto/demo_grpc/simple_router_mgr.cpp, BUT WAS MODIFIED 
* UNDER COMPLIANCE WITH THE APACHE 2.0 LICENCE FROM THE ORIGINAL WORK OF THE COMPANY Barefoot Networks, Inc. THE FOLLOWING IS THE 
* COPYRIGHT OF THE ORIGINAL DOCUMENT:
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>
#include "uint128.h"
#include <algorithm>
#include <random>
#include <iomanip>
#include <cstdint>
#include <fstream>
#include <memory>
#include <streambuf>
#include <string>


#include "routerController.h"
#include <fstream>

#include <arpa/inet.h>
#include <ctime>

#include <boost/bind.hpp>

#include <google/protobuf/text_format.h>

#include "p4/tmp/p4config.grpc.pb.h"

#include <google/rpc/code.pb.h>
#include "p4/v1/p4runtime.grpc.pb.h"
#include <p4/tmp/p4config.grpc.pb.h>
#include <grpc++/grpc++.h>

#include <google/protobuf/util/message_differencer.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>


#include <future>
#include <limits>
#include <set>
#include "PI/proto/p4info_to_and_from_proto.h" 

#include "google/rpc/code.pb.h"
#define CPU_PORT static_cast<uint16_t>(64)
#include <bits/stdc++.h>

int tactile_id=1;
namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

using grpc::ClientContext;
using grpc::Status;
using grpc::ClientReaderWriter;
int flow_id = 253;
std::string subnet_tactile = "200.0.0.0";


namespace {

enum CPU_REASON {
  NO_ARP_ENTRY = 0,
  ARP_MSG = 1,
  DATA_PKT = 2,
  LLDP_PKT = 3,
  SOURCE_FLOW = 4,
  SLICE_SWITCH = 7
};

auto set_election_id = [](p4v1::Uint128 *election_id) {
    election_id->set_high(0);
    election_id->set_low(1);
};


size_t set_cpu_header(cpu_header_t *cpu_header, uint16_t reason, uint16_t port, uint16_t device_id) {
  memset(cpu_header->zeros, 0, sizeof(cpu_header->zeros));
  cpu_header->reason = htons(reason);
  cpu_header->port = htons(port);
  cpu_header->dev_id = htons(device_id);
  return sizeof(*cpu_header);
}

size_t set_eth_header(eth_header_t *eth_header, const unsigned char (&dst_addr)[6], const unsigned char (&src_addr)[6], uint16_t ethertype) {
  memcpy(eth_header->dst_addr, dst_addr, sizeof(dst_addr));
  memcpy(eth_header->src_addr, src_addr, sizeof(src_addr));
  eth_header->ethertype = htons(ethertype);
  return sizeof(*eth_header);
}

size_t set_arp_header(arp_header_t *arp_rep, uint16_t opcode, const unsigned char (&hw_src_addr)[6], uint32_t proto_src_addr, const unsigned char (&hw_dst_addr)[6], uint32_t proto_dst_addr) {
  arp_rep->hw_type = 1;
  arp_rep->hw_type = htons(arp_rep->hw_type);
  arp_rep->proto_type = 0x800;
  arp_rep->proto_type = htons(arp_rep->proto_type);
  arp_rep->hw_addr_len = sizeof(hw_src_addr);
  arp_rep->proto_addr_len = sizeof(proto_src_addr);
  arp_rep->opcode = htons(opcode);
  memcpy(arp_rep->hw_src_addr, hw_src_addr, sizeof(hw_src_addr));
  arp_rep->proto_src_addr = htonl(proto_src_addr);
  memcpy(arp_rep->hw_dst_addr, hw_dst_addr, sizeof(hw_dst_addr));
  arp_rep->proto_dst_addr = htonl(proto_dst_addr);
  return sizeof(*arp_rep);
}

}  // namespace

MgrHandler::MgrHandler() { 
}

void RouterController::send_lldp_packet(Iface& it) {
  uint16_t port = it.port_num;
  size_t rep_size = sizeof(cpu_header_t); 
  rep_size += sizeof(eth_header_t);
  std::unique_ptr<char []> rep(new char[rep_size]);
  size_t offset = 0;
  cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
  offset += set_cpu_header(cpu_header, LLDP_PKT, port, this->dev_id);
  unsigned char broadcast_addr[6];
  memset(broadcast_addr, 0xff, sizeof(broadcast_addr));
  eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(rep.get() + offset);
  offset += set_eth_header(eth_header, broadcast_addr, it.mac_addr, 0x88CC);
  gettimeofday (&it.timestamp, NULL);
  send_packetout(rep.get(), rep_size);
  return;
  
  
}

Networkgraph* MgrHandler::network = new Networkgraph(); 
std::set<int> MgrHandler::devID = {}; 

uint64_t ntohll(uint64_t value) {
    static const int num = 42;

    if (*reinterpret_cast<const char*>(&num) == num)
    {
        const uint32_t high_part = ntohl(static_cast<uint32_t>(value >> 32));
        const uint32_t low_part = ntohl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));

        return (static_cast<uint64_t>(low_part) << 32) | high_part;
    } else
    {
        return value;
    }
}

void parse_lldp(lldp_header_t &lldp_header1) {
      lldp_header1.time_ingress = ntohll(lldp_header1.time_ingress);
      lldp_header1.deq_timedelta = ntohl(lldp_header1.deq_timedelta);
      lldp_header1.deq_qdepth = ntohs(lldp_header1.deq_qdepth);
      lldp_header1.enq_qdepth = ntohs(lldp_header1.enq_qdepth);
      lldp_header1.port = ntohs(lldp_header1.port);
      lldp_header1.dev_id = ntohs(lldp_header1.dev_id);
}

void print_lldp_statistics(lldp_header_t& h1, lldp_header_t& h2, int rec) {

  std::cout<<"LINK "<< h1.dev_id <<h1.port << " - s"<<rec<<h2.port <<std::endl;
  std::cout<<"time_ingress : "<< h1.time_ingress << " " <<rec<<": "<< h2.time_ingress << std::endl; 
  std::cout<<"deq_qdepth : "<< h1.deq_qdepth << " " <<rec<<": "<< std::to_string(h2.deq_qdepth) << std::endl; 
  std::cout<<"deq_timedelta : "<< h1.deq_timedelta << " " <<rec<<": "<< std::to_string(h2.deq_timedelta) << std::endl; 

}

struct PacketHandler : public MgrHandler {
  RouterController* rec;
	  PacketHandler(RouterController *mgr, Packet &&pkt_copy):MgrHandler(),pkt_copy(std::move(pkt_copy)) { 
	  	rec=mgr;
  }

  void operator()() {
    
    	struct timeval t_start;
    	gettimeofday (&t_start, NULL);
    	char *pkt = pkt_copy.data();
    	size_t size = pkt_copy.size();
    	size_t offset = 0;
    	cpu_header_t cpu_hdr;
	ipv4_header_t ip_hdr;
   	if ((size - offset) < sizeof(cpu_hdr)) return;
   	char zeros[8];
   	memset(zeros, 0, sizeof(zeros));
   	if (memcmp(zeros, pkt, sizeof(zeros))) return;
    	memcpy(&cpu_hdr, pkt, sizeof(cpu_hdr));
    	cpu_hdr.reason = ntohs(cpu_hdr.reason);
	cpu_hdr.source_ingress = ntohs(cpu_hdr.source_ingress);
    	cpu_hdr.port = ntohs(cpu_hdr.port);
    	offset += sizeof(cpu_hdr);
	if ((size - offset) < sizeof(eth_header_t)) return;
	offset += sizeof(eth_header_t);
	switch (cpu_hdr.reason) {
		case NO_ARP_ENTRY: {
			std::cout<<"NO_ARP_ENTRY CPU packet received!!"<<std::endl;
			if ((size - offset) < sizeof(ipv4_header_t)) return;
	      		memcpy(&ip_hdr, pkt + offset, sizeof(ip_hdr));
	      		ip_hdr.dst_addr = ntohl(ip_hdr.dst_addr);
	      		rec->handle_ip(std::move(pkt_copy), ip_hdr.dst_addr);
			break;
		}
		case ARP_MSG: {
			std::cout<<"ARP_MSG CPU packet received!!"<<std::endl;
	      		if ((size - offset) < sizeof(arp_header_t)) return;
	      		arp_header_t arp_header;	
	      		memcpy(&arp_header, pkt + offset, sizeof(arp_header));
	      		arp_header.hw_type = ntohs(arp_header.hw_type);
	      		arp_header.proto_type = ntohs(arp_header.proto_type);
	      		arp_header.opcode = ntohs(arp_header.opcode);
	      		arp_header.proto_src_addr = ntohl(arp_header.proto_src_addr);
	      		arp_header.proto_dst_addr = ntohl(arp_header.proto_dst_addr);
	      		rec->handle_arp(arp_header);
			break;
		}		
		case DATA_PKT: {
			std::cout<<"DATA_PKT CPU packet received!!"<<std::endl;
	      		if ((size - offset) < sizeof(ipv4_header_t)) return;
	      		memcpy(&ip_hdr, pkt + offset, sizeof(ip_hdr));
	      		offset += sizeof(ip_hdr);
	      		ip_hdr.src_addr = ntohl(ip_hdr.src_addr);
	      		ip_hdr.dst_addr = ntohl(ip_hdr.dst_addr);
	      		//ip_hdr.tos = ntohl(ip_hdr.tos);
			//std::cout<<"TOS: "<<uint_to_string(ip_hdr.tos)<<std::endl;
	      		int src_node = rec->dev_id;
	      		int dst_node = MgrHandler::network->findDestinationNode(ip_hdr.dst_addr).first;
	      		if (dst_node != -1) {
	        		if (rec->dev_id == src_node || rec-> dev_id == dst_node) rec->handle_ip_routing_local(std::move(pkt_copy), ip_hdr.src_addr, ip_hdr.dst_addr, ip_hdr.tos); //both src and dst connected to the same switch
	        		if (src_node!=dst_node) {
					if (ip_hdr.tos!=0) {
						rec-> tactile_flow = true; //tactile flow
						std::cout<<"tactile_flow packet received!!"<<std::endl;
					}
					MgrHandler::network->getRoute(src_node, dst_node, ip_hdr.dst_addr, ip_hdr.tos, cpu_hdr.reason, rec, "ospf", -1, rec->tactile_flow);

	        		}
	        		rec->send_packetout(pkt_copy.data(), pkt_copy.size());
	      		} else std::cout<<"Destination network not found!"<< ip_hdr.dst_addr <<"\n";
			break;
		}
		case LLDP_PKT: {
	    		if ((size - offset) < sizeof(lldp_header_t)) return;
	     		lldp_header_t lldp_header1,lldp_header2;
	      		memcpy(&lldp_header1, pkt + offset, sizeof(lldp_header1));
	      		offset += sizeof(lldp_header1);
	      		memcpy(&lldp_header2, pkt + offset, sizeof(lldp_header2));
	      		parse_lldp(lldp_header1);
	      		parse_lldp(lldp_header2);
	      		struct timeval now;
	      		gettimeofday (&now, NULL);
	      		RouterController* router1 = MgrHandler::network->getNodes()[lldp_header1.dev_id-2];
	      		struct timeval sent = router1->ifaces[lldp_header1.port-1].timestamp;
	      		int lldpdelay = ((now.tv_sec - sent.tv_sec)*1000000L +now.tv_usec) - sent.tv_usec;
	      		network->addEdge(std::pair<int,uint16_t>((int)lldp_header1.dev_id, (uint16_t)lldp_header1.port), std::pair<int,uint16_t>((int)rec->dev_id, (uint16_t)lldp_header2.port), lldp_header1, lldp_header2, lldpdelay);
			break;
		}
	} 	
  }

  Packet pkt_copy;
};


struct ConfigUpdateHandler : public MgrHandler {
  ConfigUpdateHandler(RouterController *mgr,
                      const std::string &config_buffer,
                      const std::string *p4info_buffer,
                      std::promise<int> &promise)
      : MgrHandler(), config_buffer(config_buffer),
        p4info_buffer(p4info_buffer), promise(promise) { rec = mgr; }

  void operator()() {
    int rc = rec->update_config_(config_buffer, p4info_buffer);
    promise.set_value(rc);
  }
  RouterController* rec;
  const std::string &config_buffer;
  const std::string *p4info_buffer;
  std::promise<int> &promise;
};

struct TableRuleHandler : public MgrHandler {
  TableRuleHandler(RouterController *mgr,
                      const std::string &table_name,
                      std::promise<int> &promise)
      : MgrHandler(), table_name(table_name), promise(promise) { rec = mgr; }

  void operator()() {
    int rc = rec->get_table_entries_(table_name);
    promise.set_value(rc);
  }
  RouterController* rec;
  const std::string table_name;
  std::promise<int> &promise;
};

class StreamChannelSyncClient {
 public:
  StreamChannelSyncClient(RouterController *simple_router_mgr,
                          std::shared_ptr<Channel> channel)
      : simple_router_mgr(simple_router_mgr),
        stub_(p4v1::P4Runtime::NewStub(channel)) {
    stream = stub_->StreamChannel(&context);
  }

  void recv_packet_in() {
    recv_thread = std::thread([this]() {
        p4v1::StreamMessageResponse packet_in;
        while (stream->Read(&packet_in)) {
          const auto &packet = packet_in.packet();
          Packet pkt_copy(packet.payload().begin(),packet.payload().end());
          simple_router_mgr->post_event(PacketHandler(simple_router_mgr, std::move(pkt_copy)));
        }
    });
  }

  void send_init(int device_id) {
    p4v1::StreamMessageRequest packet_out_init;
    packet_out_init.mutable_arbitration()->set_device_id(device_id);
    stream->Write(packet_out_init);	 
  }

  void send_packet_out(std::string bytes) {
    p4v1::StreamMessageRequest packet_out;
    packet_out.mutable_packet()->set_payload(std::move(bytes));
    stream->Write(packet_out);
  }

 private:
  RouterController *simple_router_mgr{nullptr};
  std::unique_ptr<p4v1::P4Runtime::Stub> stub_;
  std::thread recv_thread;
  ClientContext context;
  std::unique_ptr<ClientReaderWriter<p4v1::StreamMessageRequest, p4v1::StreamMessageResponse> > stream;
};




RouterController::RouterController(int dev_id, boost::asio::io_service &io_service, std::shared_ptr<Channel> channel, int mon_interval_2): dev_id(dev_id), io_service(io_service), work_member(io_service), pi_stub_(p4v1::P4Runtime::NewStub(channel)),
      packet_io_client(new StreamChannelSyncClient(this, channel)) {
      
      if (this->dev_id != 2) this->thread =  std::thread([&]{io_service.run(); });

}

RouterController::~RouterController() {
  in_a_row=0;
}

int RouterController::assign(const std::string &config_buffer, const std::string *p4info_buffer) {
  if (assigned) return 0;

  p4configv1::P4Info p4info_proto;
  if (!p4info_buffer) {
    pi_add_config(config_buffer.c_str(), PI_CONFIG_TYPE_BMV2_JSON, &p4info);
    p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
  } else {
    google::protobuf::TextFormat::ParseFromString(
        *p4info_buffer, &p4info_proto);
    pi::p4info::p4info_proto_reader(p4info_proto, &p4info);
  }
  p4v1::SetForwardingPipelineConfigRequest request;
  request.set_device_id(dev_id);
  request.set_action(
      p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT);
  auto config = request.mutable_config();
  config->set_allocated_p4info(&p4info_proto);
  p4::tmp::P4DeviceConfig device_config;
  auto extras = device_config.mutable_extras();
  auto kv = extras->mutable_kv();
  (*kv)["port"] = "909"+std::to_string(dev_id);

  
  device_config.set_reassign(true);
  device_config.set_device_data(config_buffer);
  device_config.SerializeToString(config->mutable_p4_device_config());

  p4v1::SetForwardingPipelineConfigResponse rep;
  ClientContext context;
  auto status = pi_stub_->SetForwardingPipelineConfig(&context, request, &rep);
  config->release_p4info();

  packet_io_client->send_init(dev_id);
  std::set<int>::iterator iter;
  if (MgrHandler::devID.find(this->dev_id) == MgrHandler::devID.end()) {
          std::cout << "New router found: "<< this->dev_id << std::endl;
          MgrHandler::devID.insert(this->dev_id);
          MgrHandler::network->addRouter(this);
        }
  packet_io_client->recv_packet_in();

  return 0;
}

namespace {

template <typename T> std::string uint_to_string(T i);

template <>
std::string uint_to_string<uint16_t>(uint16_t i) {
  i = ntohs(i);
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

template <>
std::string uint_to_string<uint8_t>(uint8_t i) {
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

template <>
std::string uint_to_string<uint32_t>(uint32_t i) {
  i = ntohl(i);
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

}  


int RouterController::add_one_entry(p4v1::TableEntry *match_action_entry) {
  p4v1::WriteRequest request;
  request.set_device_id(dev_id);
  auto update = request.add_updates();
  update->set_type(p4v1::Update_Type_INSERT);
  auto entity = update->mutable_entity();
  entity->set_allocated_table_entry(match_action_entry);

  p4v1::WriteResponse rep;
  ClientContext context;
  Status status = pi_stub_->Write(&context, request, &rep);

  entity->release_table_entry();
  return 0;
}

int RouterController::update_one_entry(p4v1::TableEntry *match_action_entry) {
  p4v1::WriteRequest request;
  request.set_device_id(dev_id);
  auto update = request.add_updates();
  update->set_type(p4v1::Update_Type_MODIFY);
  auto entity = update->mutable_entity();
  entity->set_allocated_table_entry(match_action_entry);

  p4v1::WriteResponse rep;
  ClientContext context;
  Status status = pi_stub_->Write(&context, request, &rep);

  entity->release_table_entry();
  std::cout<<"ENTRY modified \n";
  return 0;
}

int
RouterController::delete_one_entry(p4v1::TableEntry *match_action_entry) {
  p4v1::WriteRequest request;
  request.set_device_id(dev_id);
  auto update = request.add_updates();
  update->set_type(p4v1::Update_Type_DELETE);
  auto entity = update->mutable_entity();
  entity->set_allocated_table_entry(match_action_entry);

  p4v1::WriteResponse rep;
  ClientContext context;
  Status status = pi_stub_->Write(&context, request, &rep);

  entity->release_table_entry();
  std::cout<<"ENTRY detelted \n";
  return 0;
}

int RouterController::add_drop_flow(uint32_t prefix, int pLen) {
  int rc = 0;

    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "drop_packet");

    p4v1::TableEntry match_action_entry;
    match_action_entry.set_table_id(t_id);

    auto mf = match_action_entry.add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "hdr.ipv4.dstAddr"));
    auto mf_lpm = mf->mutable_lpm();
    mf_lpm->set_value(uint_to_string(prefix));
    mf_lpm->set_prefix_len(pLen);

    auto entry = match_action_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);

    rc = add_one_entry(&match_action_entry);

  return rc;
}


int RouterController::add_route_(uint32_t prefix, int pLen, uint32_t nhop, uint8_t tos, uint16_t port, UpdateMode update_mode) {
  int rc = 0;

  if (update_mode == UpdateMode::DEVICE_STATE) {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_nhop");

    p4v1::TableEntry match_action_entry;
    match_action_entry.set_table_id(t_id);

    auto mf = match_action_entry.add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "hdr.ipv4.dstAddr"));
    auto mf_lpm = mf->mutable_lpm();
    mf_lpm->set_value(uint_to_string(prefix));
    mf_lpm->set_prefix_len(pLen);

    auto entry = match_action_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);
    {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "nxtHop"));
      param->set_value(uint_to_string(nhop));

    }
    {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "port"));
      param->set_value(uint_to_string(port));
    }

    rc = add_one_entry(&match_action_entry);
  }

  if (update_mode == UpdateMode::CONTROLLER_STATE) {
    next_hops[nhop] = port;
  }

  return rc;
}

int RouterController::delete_route_(uint32_t prefix, int pLen, uint32_t nhop, uint8_t tos, uint16_t port, UpdateMode update_mode) {
  int rc = 0;

  if (update_mode == UpdateMode::DEVICE_STATE) {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_nhop");

    p4v1::TableEntry match_action_entry;
    match_action_entry.set_table_id(t_id);

    auto mf = match_action_entry.add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "hdr.ipv4.dstAddr"));
    auto mf_lpm = mf->mutable_lpm();
    mf_lpm->set_value(uint_to_string(prefix));
    mf_lpm->set_prefix_len(pLen);

    auto mf_e = match_action_entry.add_match();
    mf_e->set_field_id(pi_p4info_table_match_field_id_from_name(p4info, t_id, "hdr.ipv4.dscp"));
    auto mf_exact = mf_e->mutable_exact();
    std::cout<<"TOS:"<<uint_to_string(tos)<<" "<<unsigned(tos)<<std::endl;
    mf_exact->set_value(uint_to_string(tos));

    auto entry = match_action_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);
    {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "nxtHop"));
      param->set_value(uint_to_string(nhop));

    }
    {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "port"));
      param->set_value(uint_to_string(port));
    }

    rc = delete_one_entry(&match_action_entry);
  }

  if (update_mode == UpdateMode::CONTROLLER_STATE) {
    next_hops[nhop] = port;
  }

  return rc;
}


int RouterController::add_route(uint32_t prefix, int pLen, uint32_t nhop, uint8_t tos, uint16_t port) {

  int rc = 0;
  rc |= add_route_(prefix, pLen, nhop, tos, port, UpdateMode::CONTROLLER_STATE);
  rc |= add_route_(prefix, pLen, nhop, tos, port, UpdateMode::DEVICE_STATE);
  return rc;
}

int RouterController::delete_route(uint32_t prefix, int pLen, uint32_t nhop, uint8_t tos, uint16_t port) {

  int rc = 0;
  rc |= delete_route_(prefix, pLen, nhop, tos, port, UpdateMode::CONTROLLER_STATE);
  rc |= delete_route_(prefix, pLen, nhop, tos, port, UpdateMode::DEVICE_STATE);
  return rc;
}




int RouterController::add_arp_entry(uint32_t addr, const unsigned char (&mac_addr)[6]) {
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "forward");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_dmac");

  p4v1::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_table_match_field_id_from_name(
      p4info, t_id, "meta.nhop_ipv4"));
  auto mf_exact = mf->mutable_exact();
  mf_exact->set_value(uint_to_string(addr));

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "dmac"));
    param->set_value(std::string(reinterpret_cast<const char *>(mac_addr), sizeof(mac_addr)));
  }

  return add_one_entry(&match_action_entry);
}

int RouterController::delete_arp_entry(uint32_t addr, const unsigned char (&mac_addr)[6]) {
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "forward");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_dmac");

  p4v1::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_table_match_field_id_from_name(
      p4info, t_id, "meta.nhop_ipv4"));
  auto mf_exact = mf->mutable_exact();
  mf_exact->set_value(uint_to_string(addr));

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "dmac"));
    param->set_value(std::string(reinterpret_cast<const char *>(mac_addr), sizeof(mac_addr)));
  }

  return delete_one_entry(&match_action_entry);
}

int RouterController::assign_mac_addr(uint16_t port, const unsigned char (&mac_addr)[6]) {
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "send_frame");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "rewrite_mac");
  //std::cout << "Adding def. rule to table send_frame: "; 
  p4v1::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_table_match_field_id_from_name(
      p4info, t_id, "standard_metadata.egress_port"));
  auto mf_exact = mf->mutable_exact();
  mf_exact->set_value(uint_to_string(port));

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "smac"));
    param->set_value(std::string(reinterpret_cast<const char *>(mac_addr),
                                 sizeof(mac_addr)));
  }

  return add_one_entry(&match_action_entry);
}

int RouterController::set_one_default_entry(pi_p4_id_t t_id, p4v1::Action *action) {
  p4v1::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);
  auto entry = match_action_entry.mutable_action();
  entry->set_allocated_action(action);
  auto rc = add_one_entry(&match_action_entry);
  entry->release_action();
  return rc;
}


int RouterController::set_default_entries() {
  int rc = 0;
  std::string actions[] = {"do_decap_lldp_cpu", "do_send_to_cpu"};
  std::string tables[] = {"decap_cpu_header", "ipv4_lpm"};
  std::string match[] = {"hdr.cpu_header.reason", "hdr.ipv4.dstAddr"};
  std::string entryValues[] = {uint_to_string(static_cast<uint16_t>(3))}; 
  for(int i = 0; i < 1; i++)  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, tables[i].c_str());
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, actions[i].c_str());
    p4v1::TableEntry match_action_entry;
    match_action_entry.set_table_id(t_id);
    auto mf = match_action_entry.add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(p4info, t_id, match[i].c_str()));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(entryValues[i]);
    auto entry = match_action_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);
    if (add_one_entry(&match_action_entry))
      std::cout << "Error when adding entry to "<< tables[i].c_str()<<"\n";
  }

  return rc;
}

void RouterController::string_to_mac(std::string line, unsigned char* hw_c){
  std::vector<std::string> tokens;
  unsigned int hw[6];
  boost::split(tokens, line, boost::is_any_of(":"));
  for (int i = 0 ; i < 6; i++) {
      unsigned int x;
      std::stringstream ss;
      ss << std::hex << tokens[i];
      ss >> x;
      hw[i]=x;
      hw_c[i]=(char)hw[i];
  }
}

int RouterController::static_config_(UpdateMode update_mode) {
  std::string name = "../routerConfigs/conf"+ std::to_string(number_nodes) + "/" + std::to_string(dev_id) + "_conf.txt";
  int if_num = 1;
  std::ifstream ifs(name);
  if (ifs.is_open()) {
  	std::string line;
    while (std::getline(ifs, line)) {
    unsigned char hw[6]; 
  	 string_to_mac(line, hw);
 	   std::getline(ifs, line);
      add_iface_(if_num++, (uint32_t)boost::asio::ip::address_v4::from_string(line).to_ulong(), hw, update_mode);
  }
  } else std::cout << "Unable to open file:"<<name;   
  return 0;
}

int RouterController::static_config() {
  int rc = 0;
  rc |= static_config_(UpdateMode::CONTROLLER_STATE);
  rc |= static_config_(UpdateMode::DEVICE_STATE);
  return rc;
}

void RouterController::send_packetout(const char *data, size_t size) {
  packet_io_client->send_packet_out(std::string(data, size));
}

void RouterController::handle_arp_request(const arp_header_t &arp_header) {
  for (const auto &iface : ifaces) {
    if (iface.ip_addr == arp_header.proto_dst_addr) {
      size_t rep_size = sizeof(cpu_header_t);
      rep_size += sizeof(eth_header_t);
      rep_size += sizeof(arp_header_t);
      std::unique_ptr<char []> rep(new char[rep_size]);
      size_t offset = 0;

      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
      offset += set_cpu_header(cpu_header, ARP_MSG, iface.port_num, dev_id);

      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(rep.get() + offset);
      offset += set_eth_header(eth_header, arp_header.hw_src_addr, iface.mac_addr, 0x0806);

      arp_header_t *arp_rep = reinterpret_cast<arp_header_t *>(rep.get() + offset);
      set_arp_header(arp_rep, 2, iface.mac_addr, iface.ip_addr, arp_header.hw_src_addr, arp_header.proto_src_addr);

      send_packetout(rep.get(), rep_size);
      return;
    }
  }
}

void RouterController::handle_arp_reply(const arp_header_t &arp_header) {
  uint32_t dst_addr = arp_header.proto_src_addr;
  add_arp_entry(dst_addr, arp_header.hw_src_addr);
  auto it = packet_queues.find(dst_addr);
  if (it != packet_queues.end()) {
    for (auto &p : it->second) {
      size_t offset = 0;
      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(p.data());
      offset += set_cpu_header(cpu_header, DATA_PKT, next_hops[dst_addr], dev_id);
      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(p.data() + offset);
      memcpy(eth_header->dst_addr, arp_header.hw_src_addr, sizeof(eth_header->dst_addr));
      std::cout << "Reinjecting data packet\n";
      send_packetout(p.data(), p.size());
    }
    packet_queues.erase(it);
  }
}

void RouterController::handle_arp(const arp_header_t &arp_header) {
  switch (arp_header.opcode) {
    case 1:  // request
      handle_arp_request(arp_header);
      break;
    case 2:  // reply
      handle_arp_reply(arp_header);
      break;
    default:
      assert(0);
  }
}

void RouterController::send_arp_request(uint16_t port, uint32_t dst_addr) {
  std::cout<<"send_arp_request \n ";
  for (const auto &iface : ifaces) {
    if (iface.port_num == port) {
      size_t rep_size = sizeof(cpu_header_t);
      rep_size += sizeof(eth_header_t);
      rep_size += sizeof(arp_header_t);
      std::unique_ptr<char []> rep(new char[rep_size]);
      size_t offset = 0;

      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
      offset += set_cpu_header(cpu_header, ARP_MSG, port, dev_id);

      unsigned char broadcast_addr[6];
      memset(broadcast_addr, 0xff, sizeof(broadcast_addr));
      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(rep.get() + offset);
      offset += set_eth_header(eth_header, broadcast_addr, iface.mac_addr, 0x0806);

      arp_header_t *arp_rep = reinterpret_cast<arp_header_t *>(rep.get() + offset);
      set_arp_header(arp_rep, 1, iface.mac_addr, iface.ip_addr, broadcast_addr, dst_addr);

      send_packetout(rep.get(), rep_size);
      return;
    }
  }
}

void RouterController::handle_ip(Packet &&pkt_copy, uint32_t dst_addr) {
  auto it = next_hops.find(dst_addr);
  if (it == next_hops.end()) return;
  PacketQueue &queue = packet_queues[dst_addr];
  queue.push_back(std::move(pkt_copy));
  send_arp_request(it->second, dst_addr);
}

void RouterController::handle_ip_routing_local(Packet &&pkt_copy, uint32_t src_addr, uint32_t dst_addr, uint8_t tos) {
  for (const auto &iface : ifaces) {
       if ((iface.ip_addr & 0xffffff00) == (dst_addr & 0xffffff00)){
            add_route(iface.ip_addr & 0xffffff00, 24, dst_addr, tos, iface.port_num);
       }
       if ((iface.ip_addr & 0xffffff00) == (src_addr & 0xffffff00)){
            add_route(iface.ip_addr & 0xffffff00, 24, src_addr, tos, iface.port_num);
       }
  }
}

void RouterController::add_iface_(uint16_t port_num, uint32_t ip_addr,
                            const unsigned char (&mac_addr)[6],
                            UpdateMode update_mode) {
  if (update_mode == UpdateMode::CONTROLLER_STATE)
    ifaces.push_back(Iface::make(port_num, ip_addr, mac_addr));
  if (update_mode == UpdateMode::DEVICE_STATE) {
    for (const auto &iface : ifaces) {
      if (iface.port_num == port_num) {
        assign_mac_addr(port_num, iface.mac_addr);
        break;
      }
    }
  }
}
 
void RouterController::add_iface(uint16_t port_num, uint32_t ip_addr,
                           const unsigned char (&mac_addr)[6]) {
  add_iface_(port_num, ip_addr, mac_addr, UpdateMode::CONTROLLER_STATE);
  add_iface_(port_num, ip_addr, mac_addr, UpdateMode::DEVICE_STATE);
}



inline unsigned int to_uint(char ch)
{
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}

void print_hex(const std::string str) {
    for (char ch : str)
    {
        std::cout << std::setfill('0') << std::setw(2) << to_uint(ch); 
    }
}


int RouterController::get_table_entries_(const std::string &table_name) {
  pi_p4_id_t table_id = pi_p4info_table_id_from_name(p4info, table_name.c_str());
  if (table_id == PI_INVALID_ID) {
    std::cout << "Trying to read unknown table.\n";
    return 1;
  }

  p4v1::ReadRequest request;
  request.set_device_id(dev_id);
  auto entity = request.add_entities();
  auto table_entry = entity->mutable_table_entry();
  table_entry->set_table_id(table_id);
  p4v1::ReadResponse rep;
  ClientContext context;
  auto reader = pi_stub_->Read(&context, request);
  std::cout<<"*******************************TABLE ENTRIES"<<dev_id<<"*******************************"<<std::endl;

  while (reader->Read(&rep)) {
    std::cout<<"Table name: "<<table_name<<std::endl;
    for (const auto &entity : rep.entities()) {
      const auto &rep_entry = entity.table_entry();
      pi_p4_id_t table_id = rep_entry.table_id();
      auto af = rep_entry.action();
      auto priority = rep_entry.priority();
      auto def = rep_entry.is_default_action();
      std::cout<<"Table:"<<table_id<<" "<<" priority: "<<priority <<" default: "<<def<<"\n";
      for (const auto &mf : rep_entry.match()) {
            std::cout<<"Match fled ID: "<< mf.field_id() << " ";
            std::cout<<pi_p4info_table_match_field_name_from_id(p4info, table_id, mf.field_id());
            if (mf.has_lpm()){
              auto mfe = mf.lpm();
              auto result = mfe.value();
              std::cout<<" Value: ";
              print_hex(result);
              std::cout << "/" << mfe.prefix_len();
            } else if (mf.has_exact()){
              auto mfe = mf.exact();
              std::cout<<" Value: ";
              print_hex(mfe.value());
            }
      }
      std::cout << "\nActon_id :"<< af.action().action_id() <<" ";
      std::cout << pi_p4info_action_name_from_id(p4info, af.action().action_id());
      for (const auto &afp : af.action().params()){
        auto result = afp.value();
        std::cout<<" param_id : "<<afp.param_id() << " "
            <<pi_p4info_action_param_name_from_id(p4info, af.action().action_id(), afp.param_id())<<" param-value: ";
            print_hex(result);
      }
      std::cout<<std::endl; 
      }
    return 0; 
    }

  std::cout << "Error when trying to read table.\n";
  return 1;
}

int RouterController::get_table_entries(const std::string &table_name) {
  std::promise<int> promise;
  auto future = promise.get_future();
  TableRuleHandler h(this, table_name, promise);
  post_event(std::move(h));
  future.wait();
  return future.get();
}

int RouterController::update_config(const std::string &config_buffer,
                               const std::string *p4info_buffer) {
  std::promise<int> promise;
  auto future = promise.get_future();
  ConfigUpdateHandler h(this, config_buffer, p4info_buffer, promise);
  post_event(std::move(h));
  future.wait();
  return future.get();
}

int RouterController::update_config_(const std::string &config_buffer,
                                const std::string *p4info_buffer) {
  std::cout << "Updating config\n";

  p4configv1::P4Info p4info_proto;
  pi_p4info_t *p4info_new;
  if (!p4info_buffer) {
    pi_add_config(config_buffer.c_str(), PI_CONFIG_TYPE_BMV2_JSON, &p4info_new);
    p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
  } else {
    google::protobuf::TextFormat::ParseFromString(
        *p4info_buffer, &p4info_proto);
    pi::p4info::p4info_proto_reader(p4info_proto, &p4info_new);
  }
  pi_p4info_t *p4info_prev = p4info;
  p4info = p4info_new;
  if (p4info_prev) pi_destroy_config(p4info_prev);

  {
    p4v1::SetForwardingPipelineConfigRequest request;
    request.set_device_id(dev_id);
    request.set_action(
        p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_SAVE);
    auto config = request.mutable_config();
    config->set_allocated_p4info(&p4info_proto);
    p4::tmp::P4DeviceConfig device_config;
    device_config.set_device_data(config_buffer);
    device_config.SerializeToString(config->mutable_p4_device_config());
    p4v1::SetForwardingPipelineConfigResponse rep;
    ClientContext context;
    auto status = pi_stub_->SetForwardingPipelineConfig(
        &context, request, &rep);
    config->release_p4info();
    assert(status.ok());
  }

  set_default_entries();
  static_config_(UpdateMode::DEVICE_STATE);

  {
    p4v1::SetForwardingPipelineConfigRequest request;
    request.set_device_id(dev_id);
    request.set_action(p4v1::SetForwardingPipelineConfigRequest_Action_COMMIT);
    p4v1::SetForwardingPipelineConfigResponse rep;
    ClientContext context;
    auto status = pi_stub_->SetForwardingPipelineConfig(
        &context, request, &rep);
    assert(status.ok());
  }

  return 0;
}



void Networkgraph::printGraph () {
  std::cout<<"******************************* GRAPH *******************************"<<std::endl;
  boost::print_graph(g, boost::get(&Vertex::dev_id, g));

}



bool Networkgraph::checkifPresent(int dev_id1, int dev_id2){
  pii item(dev_id1, dev_id2);
  if (G->find(item) == G->end()) return false;
  return true;
}


void Networkgraph::addEdge(std::pair<int,uint16_t> node1, std::pair<int,uint16_t> node2, lldp_header_t& weight,lldp_header_t &weight2, int lldpdelay){
  const auto iter1 = findVertex(node1.first);
  const auto iter2 = findVertex(node2.first);
  std::pair<edge_t, bool> edg = boost::edge(*iter1,*iter2,g);
  if (edg.second == false) {
          edg = boost::add_edge(*iter1,*iter2,g);
          if (edg.second == true) std::cout << "Edge found! switch:"<<node1.first<<" port:"<<node1.second<<" - switch:"<<node2.first<<" port:"<<node2.second<<"\n";
  }  

  edge_t e = edg.first;
  g[e].time_ingress = weight2.time_ingress;
  g[e].deq_timedelta = weight.deq_timedelta;
  g[e].deq_qdepth = weight.deq_qdepth;
  g[e].deq_qdepth = weight.enq_qdepth;
  g[e].ospfWeight = 1;
  g[e].numRec++;
  g[e].propRTT=(g[e].propRTT + abs(weight.time_ingress - weight2.time_ingress))/g[e].numRec; //g[e].propRTT + (lldpdelay - weight.deq_timedelta - weight2.deq_timedelta))/g[e].numRec;
  g[e].interfaces.push_back(node1);
  g[e].interfaces.push_back(node2);
  //std::cout << "switch:"<<node1.first<<" port:"<<node1.second<<" - switch:"<<node2.first<<" port:"<<node2.second<<": "<<g[e].propRTT<<"\n";

}

void Networkgraph::addRouter(RouterController* mgr) {
  devID.insert(mgr->dev_id);
  routers.push_back(mgr);
  vertex_t nodeAdd = boost::add_vertex(g);
  numRouters++;
  g[nodeAdd].dev_id = mgr->dev_id;
  g[nodeAdd].m = mgr;
}

RouterController* Networkgraph::getNode(int dev_id){
  return routers[dev_id-2];
}


void Networkgraph::getRoute(int src, int dst, uint32_t dst_addr, uint8_t tos, uint16_t reason, RouterController* rec, std::string weight, int numFlow, bool tactile_flow){
  const auto src_node = findVertex(src);
  std::cout<<"Installing a new route \n";
  std::vector<int> distances(boost::num_vertices(g));
  std::vector<vertex_t> predecessors(boost::num_vertices(g));

  if (weight == "ospf") {
  boost::dijkstra_shortest_paths(g, *src_node, boost::weight_map(boost::get(&Edge::propRTT,g))
                                 .distance_map(boost::make_iterator_property_map(distances.begin(), boost::get(boost::vertex_index,g)))
                                 .predecessor_map(boost::make_iterator_property_map(predecessors.begin(), boost::get(boost::vertex_index,g)))
                                 );
  } 
  // Extract the shortest path from src to dst.
  path_t path;
  vertex_t v = *findVertex(dst);
  int totalDist(0);

  std::cout<<"Nodes: ";
  for(vertex_t u = predecessors[v]; u != v; v=u, u=predecessors[v]) {
    std::cout<<predecessors[v]<<" ";
    totalDist += distances[v];
    std::pair<edge_t,bool> edge_pair = boost::edge(u,v,g);
    path.push_back( edge_pair.first );
  }
  
  std::cout<<"\tDistance:"<<totalDist<<"\n";
  if (tos!=0 && totalDist >= latency) {
    	std::cout<<predecessors[v]<<"Connection not possible! The flow will be blocked.";
	rec->add_drop_flow(dst_addr & 0xffffff00, 24);	//block
	return;
  }

  for(path_t::reverse_iterator riter = path.rbegin(); riter != path.rend(); ++riter) {
    vertex_t u_tmp = boost::source(*riter, g);
    vertex_t v_tmp = boost::target(*riter, g);
    edge_t   e_tmp = boost::edge(u_tmp, v_tmp, g).first;
    int nhop_port = g[e_tmp].interfaces[1].second;
    RouterController* mgr = g[u_tmp].m;
    auto nhop = g[v_tmp].m->ifaces[nhop_port-1];
    uint16_t port = g[e_tmp].interfaces[0].second;
    if (reason == DATA_PKT){
      mgr->add_route(dst_addr & 0xffffff00, 24, nhop.ip_addr, tos, port);
      mgr->add_arp_entry(nhop.ip_addr, nhop.mac_addr);
      int result = system("setup_queues.sh");
      if (result != 0) std::cout<<"Errors occured while configuring the queues!";
    } 
  } 
}
vertex_iter Networkgraph::findVertex (const int value){
  vertex_iter vi, vi_end;
    for (boost::tie(vi, vi_end) = vertices(g); vi != vi_end; ++vi) {
        if(g[*vi].dev_id == value) return vi;
    }
    return vi_end;
}


void Networkgraph::doNetworkDiscovery() {
  boost::asio::io_service io;

  for (;;) {

    for(unsigned int i = 0; i < getNumberRouters(); i++) {
      RouterController* router = getNodes()[i];
      for (auto &it : router->ifaces ){
        usleep(10);
        router->send_lldp_packet(it);
      }
    }

    boost::asio::deadline_timer t(io, boost::posix_time::seconds(mon_interval));
    t.wait();
  }
}


void Networkgraph::GetAllRules() {
    for (unsigned int i = 0; i < numRouters; i++ ) routers[i]->get_table_entries("ipv4_lpm");
    for (unsigned int i = 0; i < numRouters; i++ ) routers[i]->get_table_entries("slice_sw");

}


std::pair<int,int> Networkgraph::findDestinationNode(uint32_t dst_addr){
  for(unsigned int i = 0; i < numRouters; i++) {
    for (const auto &iface : routers[i]->ifaces) {
       if ((iface.ip_addr & 0xffffff00) == (dst_addr & 0xffffff00)){
            return std::pair<int,int>(routers[i]->dev_id, iface.port_num);
       }
    }
  }
  return std::pair<int,int>(-1,-1);
}





