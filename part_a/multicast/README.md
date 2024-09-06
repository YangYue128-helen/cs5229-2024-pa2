# Implementing Multicast

## Introduction

In our very first assignment, to get you familiar with the basics of P4, and programmable network, we want to start from writting a customized "multicast" function. 

(Note: We will define a customized function, which could be very different from the standard multicast protocols. We want to show you that with programmable network, we can customize a lot of functions without limited by the standards.)

Sometimes, one copy of data can be requested by multiple hosts. To save the network bandwidth of source host, performing multicast in the network might be a good option. 

In this assignment, let's implement a customized multicast function with P4. 

The topology we will use for this exercise is like this. It is a single switch that connects three hosts as follow:

                         h2
                        /
                       /
              h1 - - s1
                       \
                        \
                         h3

We want the users to freely decide which hosts they want to multicast their messages to. To do so, we will define a customized packet header `multicast_grp`, it works as a tag to tell the switch that which group of hosts this packet should be sent to.

The `multicast_grp` header looks like (Just a 16-bit number):
```
header multicast_grp_t {
    bit<16> mcast_grp; 
    // if 0: treat as unicast; 
    // if others: do multicast;
}
```

If a packet contains `multicast_grp` header, the switch check the value in it and decide multicast/unicast action. If there's no `multicast_grp` header, we just perform L2-forwarding (forward base on MAC address) on the packet.

We have already defined some multicast groups in the switch runtime (it's defined in `topo/s1-runtime.json`): 
- Group 12: h1, h2
- Group 13: h1, h3
- Group 23: h2, h3
- Group field is 0: treat as unicast (l2 forwarding)

Before you start dirty your hands. There's one additional thing we want you to implement. It's about the MAC address setting. 

In this assignment, for the ease of implementation, the MAC address of testing multicast packets from sender is randomly chosen from the target group. 

Before sending the multicast to receivers, we wish the packets received by the receivers have their corresponding destination mac address. 

For example:
- h1: send a packet (h1 -> h2 / multicast to group 23 / data)
- switch: received this multicast packet, noted it should multicast to h2 and h3, do the forwarding, and edit the destination mac address to h2 / h3
- h2: receive packet (h1 -> h2 / multicast to group 23 / data)
- h3: receive packet (h1 -> **h3** / multicast to group 23 / data)

Now you can start writing the code!

(Comment: Do you see the amazing freedom that programmable networks offer?)

Our P4 program will be written for the V1Model architecture implemented on
P4.org's bmv2 software switch. The architecture file for the V1Model can be
found at: /usr/local/share/p4c/p4include/v1model.p4. This file describes the
interfaces of the P4 programmable elements in the architecture, the supported
externs, as well as the architecture's standard metadata fields. We encourage
you to take a look at it.

## Step 1: Run the (incomplete) starter code

The directory with this README also contains a skeleton P4 program,
`multicast.p4`, which initially drops all packets. Your job will be to extend
this skeleton program to properly forward Ethernet packets.

Before that, let's compile the incomplete `multicast.p4` and bring up a switch
in Mininet to test its behavior.

1. In your shell, run:
   ```bash
   make run
   ```
   This will:
   * compile `multicast.p4`, and
   * start the topology in Mininet and configure all switches with
   the appropriate P4 program + table entries, and
   * configure all hosts with the commands listed in
   [pod-topo/topology.json](./pod-topo/topology.json)

2. You should now see a Mininet command prompt. Try to ping between
   hosts in the topology:
   ```bash
   mininet> h1 ping h2
   mininet> pingall
   ```
3. Type `exit` to leave each xterm and the Mininet command line.
   Then, to stop mininet:
   ```bash
   make stop
   ```
   And to delete all pcaps, build files, and logs:
   ```bash
   make clean
   ```

The ping can reach, but the multicast functions are not implemented yet. Next, you should start writting the code for required functions.

### A note about the control plane

A P4 program defines a packet-processing pipeline, but the rules within each
table are inserted by the control plane. When a rule matches a packet, its
action is invoked with parameters supplied by the control plane as part of the
rule.

In this exercise, we have already implemented the control plane logic for you.
As part of bringing up the Mininet instance, the `make run` command will install
packet-processing rules in the tables of each switch. These are defined in the
`sX-runtime.json` files, where `X` corresponds to the switch number.

**Important:** We use P4Runtime to install the control plane rules. The
content of files `sX-runtime.json` refer to specific names of tables, keys, and
actions, as defined in the P4Info file produced by the compiler (look for the
file `build/basic.p4.p4info.txt` after executing `make run`). Any changes in the P4
program that add or rename tables, keys, or actions will need to be reflected in
these `sX-runtime.json` files.

A fixed runtime rule is not enough for actual production demands. So there's APIs you can use in Python/C++ to dynamically interact with programmable data planes. This is super useful with we want to build advance functions inside our smart network. 

But this part is too complex for this assignment so we won't talk about it here. Just use the fixed rules we provide to you. 

## Step 2: Implement L2 Multicast

The `multicast.p4` file contains a skeleton P4 program with key pieces of logic
replaced by `TODO` comments. Your implementation should follow the structure
given in this file---replace each `TODO` with logic implementing the missing
piece.

## Step 3: Run your solution

Follow the instructions from Step 1. This time, you should be able to:

1. Successfully ping between `h1`, `h2` and `h3` (To prove the connection is OK)
```bash
mininet> h1 ping h2
mininet> pingall
```
2. Successfully run `iperf` between `h1`, `h2` and `h3` (To prove normal traffic can be forwarded)
```bash
# Open bash on each virtual host
# Note: run in the VM desktop UI, because if you run in a ssh session, there will be error of "no display".
mininet> xterm h1 h2

# at one host, run iperf server
"Node:h1"
iperf -s

# at another host, run iperf client
"Node:h2"
iperf -c <iperf server IP Address>
```
3. Run multicast program between hosts (To prove our special function is OK)
```bash
# Open bash on each virtual host
# Note: run in the VM desktop UI, because if you run in a ssh session, there will be error of "no display".
mininet> xterm h1 h2 h3

# run receiver
"Node:h2"
python3 ./receive.py

"Node:h3"
python3 ./receive.py

# Test no multicast:
# at h1, run sender
"Node:h1"
python3 ./send.py 0 2 'Call it what you want'
# python3 ./send.py <whether multicast 0/1> <which host to send to 1/2/3> <message content>

# You should be able to see the output at h2, and no message is received at h3

# Test multicast:
# at h1, run
"Node:h1"
python3 ./send.py 1 2 'Mariners Apartment Complex'

# You should be able to see the output at both h2 and h3
```

### Troubleshooting

There are several problems that might manifest as you develop your program:

1. `multicast.p4` might fail to compile. In this case, `make run` will
report the error emitted from the compiler and halt.

2. `multicast.p4` might compile but fail to support the control plane rules in
the `s1-runtime.json` file that `make run` tries to install using P4Runtime. In
this case, `make run` will report errors if control plane rules cannot be
installed. Use these error messages to fix your `multicast.p4` implementation.

3. `multicast.p4` might compile, and the control plane rules might be installed,
but the switch might not process packets in the desired way. The `logs/sX.log`
files contain detailed logs that describing how each switch processes each
packet. The output is detailed and can help pinpoint logic errors in your
implementation.

#### Cleaning up Mininet

In the latter two cases above, `make run` may leave a Mininet instance
running in the background. Use the following command to clean up
these instances:

```bash
make stop
```

And you can also clean up the temporary and output files with this to restart the testing more deeply:

```bash
make clean
```

If there's still some issues with the compiler or mininet, you may also try reboot the VM. 

```bash
sudo reboot now
```

## Relevant Documentation

The documentation for P4_16 and P4Runtime is available [here](https://p4.org/specs/)

All excercises in this repository use the v1model architecture, the documentation for which is available at:

1. The BMv2 Simple Switch target document accessible [here](https://github.com/p4lang/behavioral-model/blob/master/docs/simple_switch.md) talks mainly about the v1model architecture.

2. The include file `v1model.p4` has extensive comments and can be accessed [here](https://github.com/p4lang/p4c/blob/master/p4include/v1model.p4).