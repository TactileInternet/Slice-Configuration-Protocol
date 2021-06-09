# Supporting scripts  

### Mininet scripts

[Mininet](http://mininet.org/) is a network emulator that allows us to create a realistic virtual network, running real kernel, switch and application code. This folder contains scripts to run 4 different topologies:

| Nodes    |      Links      |  File | 
|----------|:---------------:|------:|
| 4  |  3 | 4node.py  | 
| 6  | 10 | 6node.py  |
| 14 | 22 | 14node.py | 
| 24 | 43 | 24node.py |

In addition, 2 tactile hosts (IP range: 200.0.0.0.0/16) and multiple non-tactile hosts (IP range: 10.0.0.0.0/16) are connected to all the switches. Tactile nodes are configured to use Network Slicing with 4 slices (TactileClients.c and TactileServer.c files), while all the non-tactile hosts generate TCP traffic using iperf (traffic belonging to non-tactile services)

### Tactile end-nodes

Tactile end-nodes send packets through 4 slices with following specifications:

| Slice    |      ToS      |  One-way latency(ms) | Rate(pps) | Rate(kbps) | Note | 
|----------|:-------------:|---------------------:|----------:|-----------:|-----:|
| 1 |  1 | 2.9 | 343 | 275| (highest dynamics) | 
| 2 |  2 | 6.8 | 146 | 117| |
| 3 |  3 | 14.7 | 67 | 53 | |
| 4 |  4 | 58.7 | 17 | 14 | (lowest dynamics) |

The size of the packets is fixed to 100B. 

To test different dynamics scenarios, a file specifing the dynamics as sequence of ToS fields (ToS.txt) must be created ([TactileClient_File.c](TactileClient_File.c))

For a simplistic approach, that send for 5 seconds on each slice, starting from 4 to 1, use [TactileClientStatic.c](TactileClientStatic.c)
## Building the code
```bash
$ gcc -o server TactileServer.c
$ gcc -o client TactileClient_File.c
```

## Starting the controller 
It is possible to start the controller inside the mininet script.

## Starting the local controller 
the local controller is used to configure the output rates on the outgoing links based on the notifications received from the switches. Thus, to enable this functionality the local controller (in the folder P4SlicingController) must be started on the host node lc (in each mininet script Xnode_with_lc.py). Forwarding rules are changed in the P4 code itself. 

## Starting measurments
To start multiple measurments run the following command:
```bash
$ bash startMultipleMeasurments.sh numMeasurments FolderName ControllerType topoSize
```
where:
* numMeasurments - number of measruemtns
* FolderName - the folder in which the measurment results will be saved
* ControllerType - type of the controller; possible choices: NoSlicing, SDNSlicing or P4Slicing
* topoSize - number of nodes; possible choices: 4, 6, 24, 14



### Copyright

Copyright (C) 2019 TU Delft Embedded and Networked Systems Group.

GPLv3 Licence. See [License](../LICENSE) file for details.


