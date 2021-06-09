#include "routerController.h"
#include <PI/pi.h>

#include <boost/asio.hpp>

#include <ctype.h>
#include <unistd.h>
#include <cstdlib>

#include <fstream>
#include <iostream>
#include <streambuf>
#include <thread>
#include "common.h"
#define PORT 8888
int mon_interval=10;
namespace {

char *opt_config_path = NULL;
char *opt_p4info_path = NULL;
bool controller_monitoring = false;
bool dataplane_monitoring = false;
int number_nodes=7;


void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "PI example controller app\n\n"
          "-c          P4 config (json)\n"
          "-p          P4Info (in protobuf text format);\n"
          "             if missing it will be generated from the config JSON\n",
          name);
}

int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:p:b:f:m:d:h")) != -1) {
    switch (c) {
      case 'c':
        opt_config_path = optarg;
        break;
      case 'p':
        opt_p4info_path = optarg;
        break;
      case 'b':
        number_nodes = (*optarg == '4') ? 4 : 7;
        break;
      case 'f':
        mon_interval = std::atoi(optarg);
        break;
      case 'm':
        controller_monitoring = (*optarg == '1') ? true : false;
        break;
      case 'd':
        dataplane_monitoring = (*optarg == '1') ? true : false;
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c' || optopt == 'p') {
          fprintf(stderr, "Option -%c requires an argument.\n\n", optopt);
          print_help(argv[0]);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n\n", optopt);
          print_help(argv[0]);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
          print_help(argv[0]);
        }
        return 1;
      default:
        abort();
    }
  }

  if (!opt_config_path) {
    fprintf(stderr, "Options -c is required.\n\n");
    print_help(argv[0]);
    return 1;
  }

  int extra_arg = 0;
  for (int index = optind; index < argc; index++) {
    fprintf(stderr, "Non-option argument: %s\n", argv[index]);
    extra_arg = 1;
  }
  if (extra_arg) {
    print_help(argv[0]);
    return 1;
  }

  return 0;
}

}  // namespace


int dev_id = 2;
int portnum = 50051;

//Networkgraph* network = new Networkgraph();

void addRouter(boost::asio::io_service& io_service, RouterController* simple_router_mgr) {

  std::ifstream istream_config(opt_config_path);
  std::string config((std::istreambuf_iterator<char>(istream_config)),
                      std::istreambuf_iterator<char>());
  int rc;
  if (!opt_p4info_path) {
    rc = simple_router_mgr->assign(config, nullptr);
  } else {
    std::ifstream istream_p4info("./advanced_tunnel.p4info.txt");
    std::string p4info_str((std::istreambuf_iterator<char>(istream_p4info)),
                           std::istreambuf_iterator<char>());
    //std::cout<<p4info_str<<std::endl;
    rc = simple_router_mgr->assign(config, &p4info_str);
  }
  (void) rc;
  assert(rc == 0);
  simple_router_mgr->set_default_entries();
  simple_router_mgr->static_config();

}

int main(int argc, char *argv[]) {

  std::cout<<argc<<std::endl;
  if (parse_opts(argc, argv) != 0) return 1;
  std::cout<< "****Currrent configuration**** Controller:" <<  controller_monitoring << " Dataplane:" << dataplane_monitoring<< " number_nodes:" << number_nodes<< " mon_interval:" <<mon_interval<<std::endl;
  boost::asio::io_service io_service;
  boost::asio::io_service::work work(io_service);
  
  
  boost::asio::io_service io_service2; 
  boost::asio::io_service::work work2(io_service2);
  boost::asio::io_service io_service3;
  boost::asio::io_service::work work3(io_service3);
  boost::asio::io_service io_service4;
  boost::asio::io_service::work work4(io_service4);
  
  auto channel = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());
  auto channel2 = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());
  auto channel3 = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());
  auto channel4 = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());
  
  RouterController* simple_router_mgr  = new RouterController(dev_id++, io_service, channel, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);
  RouterController* simple_router_mgr2 = new RouterController(dev_id++, io_service2, channel2, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);
  RouterController* simple_router_mgr3 = new RouterController(dev_id++, io_service3, channel3, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);
  RouterController* simple_router_mgr4 = new RouterController(dev_id++, io_service4, channel4, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);

  addRouter(io_service, simple_router_mgr);
  addRouter(io_service2, simple_router_mgr2);
  addRouter(io_service3, simple_router_mgr3);
  addRouter(io_service4, simple_router_mgr4);



  std::thread t1 = MgrHandler::network->spawn(); 

  std::cout<<"\nNETWORK : "<<MgrHandler::network->getNumberRouters()<<"\n";
  boost::asio::io_service io_service5;
  boost::asio::io_service::work work5(io_service5);
  boost::asio::io_service io_service6;
  boost::asio::io_service::work work6(io_service6);
  //boost::asio::io_service io_service7;
  //boost::asio::io_service::work work7(io_service7);

  if (number_nodes!=4){

  
  auto channel5 = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());
  auto channel6 = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());
  //auto channel7 = grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials());

  RouterController* simple_router_mgr5 = new RouterController(dev_id++, io_service5, channel5, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);
  RouterController* simple_router_mgr6 = new RouterController(dev_id++, io_service6, channel6, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);
  //RouterController* simple_router_mgr7 = new RouterController(dev_id++, io_service7, channel7, controller_monitoring, dataplane_monitoring, number_nodes, mon_interval);

  addRouter(io_service5, simple_router_mgr5);
  addRouter(io_service6, simple_router_mgr6);
  //addRouter(io_service7, simple_router_mgr7);
  }
  std::thread run_thread5([&]{io_service5.run(); });
  std::thread run_thread6([&]{io_service6.run(); });
  //std::thread run_thread7([&]{io_service7.run(); });
    

  std::thread run_thread2([&]{io_service2.run(); });
  std::thread run_thread3([&]{io_service3.run(); });
  std::thread run_thread4([&]{io_service4.run(); });
  io_service.run();
  
  //std::thread run_thread([&]{ io_service.run(); });

  assert(0);
}

