# P4 Files

This folder contains 3 files, for our Dynamic Network Slicing solition (P4 + Slicing), as well as for the two basline solutions (NoSlicing and SDN + Slicing). See [paper](http://iccps.acm.org/2020/) for details. 

### P4 + Slicing 

This file implements both the edge, and core functionality of the Slice Configuration protocol (see slice_conf_t header in [P4Slicing.p4](P4Slicing.p4)) This protocols is used to create/destroy the slices on-the-fly in the data-plane (see paper for details). 

### SDN + Slicing 

This file implements an approach that uses an SDN controller to compute and install a new slice each time a switch occurs (SDN + Slicing). Thus all packets indicating a switch are sent to the controller (cpu port) that rerouts the traffic and reconfigures the reserved bandwidth. Consequently, when a tactile flow starts, the switches will forward the request to the controller, that installs the route corresponding to the first used slice. Every time a slice switch occurs, a new packet is sent to the controller that, after recalculating the route, changes the forwarding rules and allocations in all the switches.

### No Slicing 
This file implements an approach that does not use slicing, but provides QoS guarantees (No Slicing) by reserving either the maximum or average bandwidth needed by the flow. However, all these actions are performed by the controller. Consequently, when a tactile flow starts, the switches will forward the request to the controller, that installs a single route that is used throught the duration of the flow.

### Compiling the P4 code

```bash
p4c-bm2-ss --std p4-16 -o file_name.json --p4runtime-files file_name.p4info.txt file_name.p4
```
file_name.json file is the JSON file format expected by BMv2 behavioral model simple_switch.
file_name.p4info.txt file contains a description of the tables and other objects from the file_name.p4 program. It is used by the central controller.

### Copyright

Copyright (C) 2019 TU Delft Embedded and Networked Systems Group.

GPLv3 Licence. See [License](../LICENSE) file for details.


