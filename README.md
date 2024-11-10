`# Packet Sniffer

This project is a **Packet Sniffer** built with Python using the Scapy library. It captures network packets and displays relevant information about each packet, including details from Ethernet, IP, TCP, UDP, and ICMP layers.

## Overview

The packet sniffer captures packets on a specified network interface and displays key information, such as:
- Timestamps
- Source and destination MAC addresses
- Source and destination IP addresses
- Protocol type
- TCP/UDP source and destination ports
- TCP flags and payload
- UDP and ICMP payloads

## Requirements

- Python 3.x
- Scapy library

You can install the Scapy library using:
```bash
pip install scapy `

**Note**: Running this script may require elevated privileges.

Usage
-----

1.  Clone the repository:

    bash

    Copy code

    `git clone https://github.com/shrutishree2004/packet-sniffer.git`

2.  Navigate to the project directory:

    bash

    Copy code

    `cd packet-sniffer`

3.  Run the script with elevated privileges:

    bash

    Copy code

    `sudo python packet_sniffer.py`

### Parameters

-   **interface**: Specify the network interface to capture packets on (e.g., `eth0`).
-   **packet_count**: Number of packets to capture before stopping.

### Sample Command

To capture 10 packets on the `eth0` interface:

bash

Copy code

`sudo python packet_sniffer.py`

### Sample Output

The output displays the captured packet details:

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
TCP Payload: b'payload_data_here'`

Functions
---------

-   **analyze_packet(packet)**: Analyzes individual packets and extracts key details based on protocol layers.
-   **start_sniffing(interface, packet_count)**: Initiates packet sniffing on the specified network interface and captures the specified number of packets.

License
-------

This project is open-source and available under the MIT License.

vbnet

Copy code

 `This README provides information on the project, its usage, and sample output, making it easy to under`
