`# Packet Sniffer with Scapy

This project is a **Python-based Packet Sniffer** that captures and analyzes network traffic on a specified network interface using the Scapy library. It provides a breakdown of each captured packet, including Ethernet, IP, TCP, UDP, and ICMP layer details.

## Table of Contents

- [Overview](#overview)

- [Features](#features)

- [Requirements](#requirements)

- [Installation](#installation)

- [Usage](#usage)

- [Example Output](#example-output)

- [Functions](#functions)

- [Customization](#customization)

- [License](#license)

## Overview

This packet sniffer captures network packets on a specified network interface and provides detailed information such as:

- Timestamp of capture

- MAC addresses (source and destination)

- IP addresses (source and destination)

- Protocol type (e.g., TCP, UDP, ICMP)

- Port numbers for TCP/UDP packets

- TCP flags and payload content

- UDP and ICMP packet details, including payload

## Features

- **Real-Time Packet Analysis**: Displays each packet's details immediately upon capture.

- **Multi-Protocol Support**: Supports Ethernet, IP, TCP, UDP, and ICMP.

- **Configurable Interface and Packet Count**: Customize the interface and number of packets to capture.

- **Detailed Logging**: Provides in-depth details for each packet layer.

## Requirements

- Python 3.x

- [Scapy](https://scapy.net/) library for packet capturing and analysis

Install the Scapy library using:

```bash

pip install scapy `

**Note**: Running this script generally requires elevated privileges to access network traffic.

Installation

------------

Clone this repository to your local machine:

bash

Copy code

`git clone https://github.com/your-username/packet-sniffer.git

cd packet-sniffer`

Usage

-----

To start capturing packets, run the script with elevated privileges:

bash

Copy code

`sudo python3 packet_sniffer.py`

### Parameters

-   **interface** (default: `eth0`): Specify the network interface to capture packets on.

-   **packet_count** (default: `10`): Define the number of packets to capture before stopping.

### Custom Command Example

To capture 20 packets on a custom interface `wlan0`, use:

bash

Copy code

`sudo python3 packet_sniffer.py --interface wlan0 --packet_count 20`

Example Output

--------------

An example of output for a captured packet:

yaml

Copy code

`[+] Packet captured at: 2023-01-01 12:00:00

Source MAC: 00:11:22:33:44:55

Destination MAC: 66:77:88:99:AA:BB

Source IP: 192.168.0.1

Destination IP: 192.168.0.2

Protocol: 6 (TCP)

Source Port: 443

Destination Port: 50432

TCP Flags: 18

TCP Payload: b'payload_data_here'

------------------------------------------------------------`

Functions

---------

-   **`analyze_packet(packet)`**: Analyzes each packet and extracts key details based on available protocol layers (Ethernet, IP, TCP, UDP, ICMP).

-   **`start_sniffing(interface="eth0", packet_count=10)`**: Initiates packet sniffing on the specified network interface and captures the desired number of packets, displaying their details in real-time.

Customization

-------------

-   **Adjust Interface and Packet Count**: Modify the `start_sniffing()` function call to specify a custom interface and capture count.

-   **Logging Additional Layers**: Modify `analyze_packet()` to include additional protocols or layers if required.

-   **File Logging**: Implement optional file logging to save captured packet details.

License

-------

This project is open-source and available under the MIT License.

rust

Copy code

 `This enhanced README includes sections for customization, detailed instructions, and more structured formatting to improve`
