# Switch Python Implementation

## Overview
The goal of this project is to model a virtual network's routing procedure. It executes **VLAN**, **STP** (Spanning Tree Protocol), and the **switching** operation.

Every switch can determine what to do with every packet it receives thanks to its own **MAC Table**.
Multiple virtual networks can exist within a single physical network thanks to **VLAN**.
By establishing a loop-free topology, switches employ **STP** to remove network loops and guarantee effective data transfer without redundancy.

## Running

```bash
sudo python3 checker/topo.py
```

This will open 9 terminals, 6 hosts and 3 for the switches. On the switch terminal you will run 

```bash
make run_switch SWITCH_ID=X # X is 0,1 or 2
```

The hosts have the following IP addresses.
```
host0 192.168.1.1
host1 192.168.1.2
host2 192.168.1.3
host3 192.168.1.4
host4 192.168.1.5
host5 192.168.1.6
```

We will be testing using the ICMP. For example, from host0 we will run:

```
ping 192.168.1.2
```

Note: We will use wireshark for debugging. From any terminal you can run `wireshark&`.

