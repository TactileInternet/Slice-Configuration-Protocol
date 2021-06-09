/* Copyright 2019 Belma Turkovic
* TU Delft Embedded and Networked Systems Group.
* 
* NOTICE: THIS FILE IS BASED ON https://github.com/p4lang/PI/tree/master/proto/demo_grpc/simple_router_mgr.h, BUT WAS MODIFIED 
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
#pragma once

#include <PI/pi.h>

#include <boost/asio.hpp>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/graph/graph_utility.hpp>

#include <grpc++/grpc++.h>
#include <fstream>
#include "p4/v1/p4runtime.grpc.pb.h"
#include <chrono>
#include <iostream>
#include <cstring>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <ctime>
#include "common.h"



using grpc::Channel;
typedef std::vector<int> vi;
typedef std::pair<int,int> pii;
typedef std::map<pii, int> vii;
#define INF 0x3f3f3f3f
//int mon_interval;
//class Networkgraph;
//Networkgraph* network;
//struct PacketHandler;

typedef std::vector<char> Packet;

struct __attribute__((packed)) cpu_header_t {
  char zeros[8];
  uint16_t reason;
  uint16_t source_ingress;
  uint16_t port;
  uint16_t dev_id;
};

struct __attribute__((packed)) arp_header_t {
  uint16_t hw_type;
  uint16_t proto_type;
  uint8_t hw_addr_len;
  uint8_t proto_addr_len;
  uint16_t opcode;
  unsigned char hw_src_addr[6];
  uint32_t proto_src_addr;
  unsigned char hw_dst_addr[6];
  uint32_t proto_dst_addr;
};

struct __attribute__((packed)) lldp_header_t {
  uint16_t dev_id;
  uint64_t time_ingress;
  uint32_t deq_timedelta;
  uint32_t deq_qdepth;
  uint32_t enq_qdepth;
  uint16_t port;
};

struct __attribute__((packed)) eth_header_t {
  unsigned char dst_addr[6];
  unsigned char src_addr[6];
  uint16_t ethertype;
};

struct __attribute__((packed)) ipv4_header_t {
  unsigned char noise1[1];
  uint8_t tos;
  unsigned char noise[10];
  uint32_t src_addr;
  uint32_t dst_addr;
};

class StreamChannelSyncClient;

#ifndef SIMPLEROUTERMGR_H
#define SIMPLEROUTERMGR_H

class RouterController {
 public:
  bool tactile_flow;
  int in_a_row;
  friend struct PacketHandler;
  friend struct ConfigUpdateHandler;
  friend struct TableRuleHandler;
  RouterController(int dev_id, boost::asio::io_service &io_service, std::shared_ptr<Channel> channel, int);
  ~RouterController();

  int assign(const std::string &config_buffer, const std::string *p4info_buffer);

  int add_route(uint32_t prefix, int pLen, uint32_t nhop, uint8_t tos, uint16_t port);
  int delete_route(uint32_t prefix, int pLen, uint8_t tos);
  int add_drop_flow(uint32_t prefix, int pLen, uint8_t);
  int set_default_entries();
  int static_config();

  void add_iface(uint16_t port_num, uint32_t ip_addr, const unsigned char (&mac_addr)[6]);
  int update_config(const std::string &config_buffer, const std::string *p4info_buffer);

  template <typename E> void post_event(E &&event) {
    io_service.post(std::move(event));
  }

  struct timeval controllerSent, controllerRec;

  struct Iface {
    uint16_t port_num;
    uint32_t ip_addr;
    unsigned char mac_addr[6];
    unsigned long delay;
    struct timeval timestamp;
    uint32_t weight;
    bool isHostPort;
    std::pair<int,int> next;
    static Iface make(uint16_t port_num, uint32_t ip_addr,
                      const unsigned char (&mac_addr)[6]) {
      Iface iface;
      iface.port_num = port_num;
      iface.ip_addr = ip_addr;
      iface.isHostPort = false;
      iface.next = std::pair<int,int>(0,0);
      memcpy(iface.mac_addr, mac_addr, sizeof(mac_addr));
      return iface;
    }
  };
  std::vector<Iface> ifaces;
  int dev_id;
  void send_lldp_packet(Iface&);
  void send_packetout(const char *data, size_t size);
  int add_arp_entry(uint32_t addr, const unsigned char (&mac_addr)[6]);
  int delete_arp_entry(uint32_t addr, const unsigned char (&mac_addr)[6]);

  int get_table_entries_(const std::string&);
  int get_table_entries(const std::string&);
  static void string_to_mac(std::string line, unsigned char* hw);

 protected:

   std::unordered_map<uint32_t, uint16_t> next_hops;

  private:

  enum class UpdateMode {
    CONTROLLER_STATE,
    DEVICE_STATE
  };

  typedef std::vector<Packet> PacketQueue;

  void handle_arp(const arp_header_t &arp_header);
  void handle_ip(Packet &&pkt_copy, uint32_t dst_addr);
  int assign_mac_addr(uint16_t port, const unsigned char (&mac_addr)[6]);
  void handle_arp_request(const arp_header_t &arp_header);
  void handle_arp_reply(const arp_header_t &arp_header);
  void send_arp_request(uint16_t port, uint32_t dst_addr);
  void handle_ip_routing_local(Packet&& pkt, uint32_t src_addr, uint32_t dst_addr, uint8_t tos);
  int add_one_entry(p4::v1::TableEntry *match_action_entry);

  int delete_one_entry(p4::v1::TableEntry *match_action_entry);
  int update_one_entry(p4::v1::TableEntry *match_action_entry);

  int set_one_default_entry(pi_p4_id_t t_id, p4::v1::Action *action);

  int add_route_(uint32_t prefix, int pLen, uint32_t nhop, uint8_t tos, uint16_t port, UpdateMode udpate_mode);
  int delete_route_(uint32_t prefix, int pLen, uint8_t tos, UpdateMode udpate_mode);
  void add_iface_(uint16_t port_num, uint32_t ip_addr, const unsigned char (&mac_addr)[6], UpdateMode update_mode);

  int static_config_(UpdateMode update_mode);

  int update_config_(const std::string &config_buffer, const std::string *p4info_buffer);


  bool assigned{false};
  std::unordered_map<uint32_t, PacketQueue> packet_queues;
  pi_p4info_t *p4info{nullptr};
  boost::asio::io_service &io_service;
  boost::asio::io_service::work work_member;
  std::thread thread;
  std::unique_ptr<p4::v1::P4Runtime::Stub> pi_stub_;
  std::unique_ptr<StreamChannelSyncClient> packet_io_client;
};
#endif

#ifndef NETWORK_H
#define NETWORK_H

struct Edge
{
  uint64_t time_ingress;
  //uint32_t enq_timestamp;
  uint32_t deq_timedelta;
  uint32_t deq_qdepth;
  uint32_t enq_qdepth;
  uint32_t ospfWeight;
  int propRTT;
  std::vector<std::pair<int,uint16_t>> interfaces;
  int in_a_row;
  int numRec;
  Edge(): time_ingress(0), deq_timedelta(0), deq_qdepth(0), enq_qdepth(0), ospfWeight(1), propRTT(0), in_a_row(0), numRec(0)  {
    interfaces = {};
  }
};

struct Vertex
{
  int dev_id;
  RouterController* m;
  Vertex(int i){
    dev_id = i;
    m= nullptr;
  }
  Vertex() {}
};

typedef boost::adjacency_list<boost::setS, boost::vecS, boost::directedS, Vertex, Edge> graph;
typedef boost::graph_traits<graph>::vertex_descriptor vertex_t;
typedef boost::graph_traits<graph>::edge_descriptor edge_t;
typedef boost::graph_traits<graph>::vertex_iterator vertex_iter;
typedef boost::graph_traits<graph>::edge_iterator edge_iter; 
typedef std::vector<edge_t> path_t;

class Networkgraph {

    vii *G;   // Graph
    graph g;
    std::vector<RouterController*> routers;
    std::set<int> devID;
    unsigned int numRouters;

public:
    int numProbePackets;

  Networkgraph(){
    numRouters = 0;
    numProbePackets=0;
    routers = {};
    G = new std::map<pii,int>();
  } 
  ~Networkgraph(){}

  void printGraph();
  bool checkifPresent(int,int);
  void addEdge(std::pair<int,uint16_t>, std::pair<int,uint16_t>, lldp_header_t&, lldp_header_t&, int);
  void getRoute(int src, int dst, uint32_t dst_addr, uint8_t tos, uint16_t reason, RouterController* rec, std::string, int, bool);
  vi Dijkstra(int);
  vertex_iter findVertex (const int v);
  RouterController* getFirst() {return routers[0];}
  std::vector<RouterController*> getNodes() {return routers;}
  RouterController* getNode (int dev_id);
  unsigned int getNumberRouters(){return numRouters;}
  void addRouter(RouterController*);
  void doNetworkDiscovery();
  void updateGraph();
  void GetAllRules();
  void deleteAllEntries(uint32_t prefix, int pLen, uint8_t tos);
  std::thread spawn() {
    return std::thread(&Networkgraph::doNetworkDiscovery, this);
  }
  std::pair<int,int> findDestinationNode(uint32_t dst_addr);

};

#endif /* NETWORK_H */


#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

struct MgrHandler {
  MgrHandler();
  static Networkgraph* network;
  static std::vector<RouterController*> routers;
  static std::set<int> devID;
};

#endif /* PACKETHANDLER_H */



