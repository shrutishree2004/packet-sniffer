from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from datetime import datetime

# Define a function to analyze captured packets
def analyze_packet(packet):
    # Extract the timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    print(f"\n[+] Packet captured at: {timestamp}")
    
    # Check if the packet has an Ethernet layer
    if packet.haslayer(Ether):
        print(f"Source MAC: {packet[Ether].src}")
        print(f"Destination MAC: {packet[Ether].dst}")
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    # Check if the packet is TCP
    if packet.haslayer(TCP):
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"TCP Flags: {packet[TCP].flags}")
        # Display Payload if any
        if packet[TCP].payload:
            print(f"TCP Payload: {bytes(packet[TCP].payload)}")

    # Check if the packet is UDP
    elif packet.haslayer(UDP):
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
        # Display Payload if any
        if packet[UDP].payload:
            print(f"UDP Payload: {bytes(packet[UDP].payload)}")

    # Check if the packet is ICMP
    elif packet.haslayer(ICMP):
        print(f"ICMP Type: {packet[ICMP].type}")
        print(f"ICMP Code: {packet[ICMP].code}")
        # Display Payload if any
        if packet[ICMP].payload:
            print(f"ICMP Payload: {bytes(packet[ICMP].payload)}")

    print("-" * 60)

# Define the main function to start packet sniffing
def start_sniffing(interface="eth0", packet_count=10):
    print(f"[*] Starting packet capture on {interface}...\n")
    sniff(iface=interface, prn=analyze_packet, count=packet_count)

if __name__ == "__main__":
    # Start sniffing on the specified interface (you can change the interface name)
    try:
        start_sniffing(interface="eth0", packet_count=10)  # Modify the interface and count as needed
    except PermissionError:
        print("[!] Please run the script with elevated privileges (sudo).")
