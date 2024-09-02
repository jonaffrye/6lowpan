# 6LoWPAN for UWB communication

This project was developed during my master’s thesis with the goal of implementing the 6LoWPAN protocol for [Ultra-Wideband (UWB)](https://en.wikipedia.org/wiki/Ultra-wideband) communication on the [GRiSP 2](https://www.grisp.org/) embedded system, developed by [Stritzinger GmbH](https://www.stritzinger.com/).
This work builds on previous work by Gwendal Laurent available on this [GitHub](https://github.com/GwendalLaurent/pmod_uwb) repository.


## Overview

The entry point of the code is the `lowpan_api` module, which acts as an API enabling the transmission IPv6 packets and reception of MAC frames. 

Key functions include:

**`sendPacket(Ipv6Pckt)`**: To send an IPv6 packet.

**`sendPacket(Ipv6Pckt, MetricEnabled)`**: To send an IPv6 packet with optional metric like compression ratio, sucess rate.

**`frameReception()`**: To receive MAC frames.

## Code Architecture

The code architecture is organized into four modules:
1. `Lowpan API` for sending IPv6 packets and receiving MAC frames.
2. `Lowpan core` which implements 6LoWPAN features including compression, fragmentation and meshing logic.
3. `Lowpan IPv6` for creating IPv6 and UDP packets.
4. `Routing Table` for managing routes between nodes.


<p align="center">
<img src="imgs/code architecture.png" width=400>
</p>


## Software testing

Software tests have been designed to validate the 6LoWPAN layer, including various exchange scenarios. 
The setup for the simulation tests is shown in the image below. In order to transmit a message, a node calls the 6LoWPAN layer, which in turn calls on the IEEE802.15.4 MAC layer. The logic is reversed for frame reception.

<p align="center">
<img src="imgs/simu setup.png" width=300>
</p>

To run these tests, use the following command:

```bash
rebar3 ct --sname test
```

## Hardware testing

For real hardware transmission and reception using the GRiSP2 board, the Robot application defined in the `robot` module includes several functions:

**`tx()`**: To performs a simple transmission to node.

**`tx_big_payload(N)`**: To transmit a large payload, where N represents the number of chunks in the payload.

**`rx()`**: To receive data.

## Robot example 
This code example below shows how to perform simple IPv6 packet transmission using the `Lowpan API`:

```bash
tx() ->
    Payload = <<"Hello world">>,
    PayloadLength = byte_size(Payload),
    IPv6Header =
        #ipv6_header{
            version = 6,
            traffic_class = 0,
            flow_label = 0,
            payload_length = PayloadLength,
            next_header = 17,
            hop_limit = 255,
            source_address = ?Node1Address,
            destination_address = ?Node2Address
        },
    Ipv6Pckt = lowpan_ipv6:buildIpv6Packet(IPv6Header, Payload),
    lowpan_api:sendPacket(Ipv6Pckt, true).
```
This example shows how to perform a frame reception using the `Lowpan API`:

```bash
rx() ->
    lowpan_api:frameReception(),
    rx().
```

## Deployement

To deploy the robot application onto the GRiSP 2 board, use the following command:

```bash
rebar3 as node1 grisp deploy
```

The current implementation allows the code to be deployed on up to five GRiSP boards. To do this, change `node1` to `nodeX`, where X is the board number. The MAC address of each GRiSP boards can be found in the config folder.

If you want to manually perform the transmissions, it can be done over serial communication, a tutorial can be found [here](https://github.com/grisp/grisp/wiki/Connecting-over-Serial).

In this case, after a successful connection, run the following command for simple transmission:

```bash
robot:tx()
```


## Hardware tests setup 

When sending data via GRiSP boards, a UWB sniffer can be used to capture the packets sent and analyse them in the Wireshark software. The sniffer configuration parameters are given below:

<p align="center">
<img src="imgs/sniffer parameters.png" width=400>
</p>

Note that when analyzing packets in Wireshark, the 6LoWPAN section may not appear, 

<p align="center">
<img src="imgs/wireshark setup 1.png" width=400>
</p>

the 6LoWPAN protocol in Wireshark should to be enable for this section to appear. To do so, you need to go to the Analyze tab, then Enabled protocols and type 6LoWPAN in the search bar, then enable it.

<p align="center">
<img src="imgs/wireshark setup 2.png" width=400>
</p>

After these steps, the 6LoWPAN section should then appear, as shown in the next figure.

<p align="center">
<img src="imgs/wireshark setup 3.png" width=400>
</p>