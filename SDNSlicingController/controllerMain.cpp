/* Copyright 2019 Belma Turkovic
* TU Delft Embedded and Networked Systems Group.
* 
* NOTICE: THIS FILE IS BASED ON https://github.com/p4lang/PI/tree/master/proto/demo_grpc/app.cpp, BUT WAS MODIFIED UNDER COMPLIANCE 
* WITH THE APACHE 2.0 LICENCE FROM THE ORIGINAL WORK OF THE COMPANY Barefoot Networks, Inc. THE FOLLOWING IS THE COPYRIGHT OF THE ORIGINAL DOCUMENT:
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
int mon_interval(10);
int number_nodes(4);

//Switch specification
int bandwidth[4] = {122500, 41250, 20000, 16250};
int latency[4] = {500000, 25000, 10000, 7000}; 
namespace {

char *opt_config_path = NULL;
char *opt_p4info_path = NULL;



void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "NoSlicing controller app\n\n"
          "-c          P4 config (json)\n"
          "-p          P4Info (in protobuf text format);\n"
          "            if missing it will be generated from the config JSON\n"
          "-m          monitoring interval (default 10 seconds) \n"
          "-n          max network nodes   (default 4) \n"	  
          "-h          print help\n",
          name);
}

int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:p:m:n:h")) != -1) {
    switch (c) {
      case 'c':
        opt_config_path = optarg;
        break;
      case 'p':
        opt_p4info_path = optarg;
        break;
      case 'm':
        mon_interval = atoi(optarg);
        break;
      case 'n':
        number_nodes = atoi(optarg);
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c' || optopt == 'p' || optopt == 'm') {
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


int dev_id  = 2;
int portnum = 50051;

void addRouter(boost::asio::io_service& io_service, RouterController* simple_router_mgr) {

  std::ifstream istream_config(opt_config_path);
  std::string config((std::istreambuf_iterator<char>(istream_config)), std::istreambuf_iterator<char>());
  int rc;
  if (!opt_p4info_path) {
    rc = simple_router_mgr->assign(config, nullptr);
  } else {
    std::ifstream istream_p4info(opt_p4info_path);
    std::string p4info_str((std::istreambuf_iterator<char>(istream_p4info)), std::istreambuf_iterator<char>());
    rc = simple_router_mgr->assign(config, &p4info_str);
  }
  (void) rc;
  assert(rc == 0);
  simple_router_mgr->set_default_entries();
  simple_router_mgr->static_config();

}

int main(int argc, char *argv[]) {

  if (parse_opts(argc, argv) != 0) return 1;
  std::cout<< "****Currrent configuration****\nnumber_nodes:" << number_nodes<< "\nmon_interval:" <<mon_interval<<std::endl;
  boost::asio::io_service io_service[number_nodes];
 
  RouterController* routers[number_nodes];
  for(int i=0; i< number_nodes; i++){
  	routers[i]  = new RouterController(dev_id++, io_service[i], grpc::CreateChannel("localhost:"+std::to_string(portnum++), grpc::InsecureChannelCredentials()), mon_interval);
	addRouter(io_service[i], routers[i]);

  }

  std::thread t1 = MgrHandler::network->spawn(); 
  io_service[0].run();

  assert(0);
}

