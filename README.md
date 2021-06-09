# Dynamic Network Slicing for the Tactile Internet - Real-Time Slice Management Framework 

Real-Time Slice Management framework enables on-demand provisioning of network resources, i.e. the resources are made available on-the-fly only when needed, similarly to computing resources in cloud environments. This way the QoS is guaranteed during the whole lifetime of a tactile application, i.e. the network is adapting its behaviour to match the current TCPS application's needs. The main components are: 
* **central SDN controller** (control-plane) 
* **Slice configuration protocol** (data-plane)

## Project Layout
```bash
├── COPYING
├── mininetScripts
├── NoSlicingController
├── P4SlicingController (central SDN controller)
├── P4src
├── P4src
│   ├── P4Slicing.p4
│   ├── NoSlicing.p4
│   └── P4Slicing.p4 (Slice configuration protocol)
├── routerConfigs
│   ├── conf14
│   ├── conf24
│   ├── conf7
│   └── conf4
└── SDNSlicingController
```
## Central controller (P4SlicingController)
For every new TCPS flow, the controller finds the appropriate routes that satisfy the end-to-end slice requirements according to the current global network state. In this implementation tactile flows are routed through 4 slices with RTTs equal to 117.4ms, 29.5ms, 13.4ms, and 5.7ms (see Repository CITE_KURIANS, and paper 'Dynamic Network Slicing for the Tactile Internet' for details)

NoSlicingController (used together with NoSlicing.p4) and SDNSlicingController (used together with SDNSlicing.p4) are used as comparison baslines (see paper for details).

## Slice Configuration Protocol
Slice Configuration Protocol is used to create/destroy the slices on-the-fly in the data-plane (see paper for details). It provides a fast update loop, enabling the switches to react quickly to the changes in the application dynamics without the need to contact the SDN controller. 
To perform the above-mentioned actions, our slice configuration protocol uses two different messages: 
* **Slice setup** message to create a new slice 
* **Slice delete** message to delete the previously used slice.
```
         0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |Type |                SliceID                  |   
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                    Length                     |
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                    FlowID                     |
      +-----+-----+-----+-----+-----+-----+-----+-----+ 
      |                  Ports Array                  |
      +-----+-----+-----+-----+-----+-----+-----+-----+
```
Protocol fields:
* Type (1 bit) - defines weather it is a slice setup or slice delete message.
* SliceID (7 bits) - identifies a set of latency/bandwidth constraints. 
* Header Length (8 bits) - number of switches on the path
* Ports array (variable) -  pre-calculated route as a sequence of output ports from all the switches on path

## Dependencies
**Required packages:**
```bash
$ apt-get install make mininet iperf3 build-essentials
```
**Installing other dependencies from source:**

Some dependencies are not available as Debian packages. Consequently, you also need to install the following from source:
* [bmv2](https://github.com/p4lang/behavioral-model) with the simple_switch_grpc target and all its dependencies
* [PI](https://github.com/p4lang/PI) and all its dependencies
* [p4c](https://github.com/p4lang/p4c) 

## Building the code

#### Compiling the P4 code

```bash
p4c-bm2-ss --std p4-16 -o P4Slicing.json --p4runtime-files P4Slicing.p4info.txt P4src/P4Slicing.p4
```
P4Slicing.json file is the JSON file format expected by BMv2 behavioral model simple_switch.
P4Slicing.p4info.txt file contains a description of the tables and other objects from the P4Slicing.p4 program. It is used by the central controller.
#### Building the controller 
```
$ ./configure
$ make
```

#### Building the local controller 
```
$ cd P4SlicingController
$ sudo gcc -o localcontroller localController.c
```

## Comparison baslines
Real-Time Slice Management Framework (P4 + Slicing) was compared to: 
* SDNSlicing (controller: SDNSlicingController, P4Code: P4src/SDNSlicing.p4) - an approach that uses an SDN controller to compute and install a new slice each time a switch occurs (without the Slice Configuration protocol)
* NoSlicing (controller: NoSlicingController, P4Code: P4src/NoSlicing.p4) - an approach that does not use slicing, but provides QoS guarantees by reserving either the maximum or average bandwidth needed by the flow.}


## Paper
Paper: https://conferences.computer.org/cpsiot/pdfs/ICCPS2020-2igU8bUaP8OG7uMv6rENFa/550100a129/550100a129.pdf
Video Presentation: https://www.youtube.com/watch?v=XGcKfRKWjvY&t=2s

To cite the paper where Dynamic Network Slicing is being introduced please use the following LaTeX bibitem.

```
@inproceedings{polachan_iccps2020,
    author = "Kurian Polachan and Belma Turkovic and T. V. Prabhakar and Chandramani Singh and Fernando A. Kuipers",
    title = {{Dynamic Network Slicing for the Tactile Internet}},
    booktitle = {{Proc. of the 11th ACM/IEEE International Conference on Cyber-Physical Systems (ACM/IEEE ICCPS 2020)}},
    year = {2020},
    month = {April}, 
    publisher = {{ACM/IEEE}}
}
```

### Copyright

Copyright (C) 2019 TU Delft Embedded and Networked Systems Group.

GPLv3 Licence. See [License](LICENSE) file for details.


