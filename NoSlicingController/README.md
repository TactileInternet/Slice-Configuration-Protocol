# NoSlicing Controller 

```bash
Usage: ./controller [OPTIONS]...
NoSlicing controller app

-c          P4 config (json)
-p          P4Info (in protobuf text format); if missing it will be generated from the config JSON
-m          monitoring interval (default 10 seconds) 
-h          print this message
-n          max network nodes (default 4) 	  

```

### Tactile flows
Tactile flows are recognized by having a Tos field different from 0. 

### Link discovery & monitoring
To route packets through the network, the controller first needs to know the network topology. In this controller app this is done using custom packets with the following header format:
```

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            device ID          |             port              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        ingress_timestamp                      |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          deq_timedelta                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           deq_qdepth                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           enq_qdepth                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* device ID (16 bit) - device ID of the switch that processed the packet.
* port (16 bits) - port to which the packet was received/sent 
* time_ingress (64 bits) - ingress timestamp
* deq_timedelta (32 bits) -  queueing delay the packet experienced on the switch
* enq_qdepth (32 bits) -  the depth of the queue at the moment before the packet is
placed in (enqueue queue length)
* deq_qdepth (32 bits) -  the depth of the queue at the moment after the packet left the queue
(dequeue queue length), 

Last 4 fields are used for the monitoring application, i.e. by periodicly sending probe packets the controller keeps track of the current state of the network. All of these fields can then be used by the controller app to find the appropriate tactile routes.

## ARP Requests

## Building the code

```
$ cd NoSlicingController
$ make
```

### Copyright

Copyright (C) 2019 TU Delft Embedded and Networked Systems Group.

GPLv3 Licence. See [License](../LICENSE) file for details.


