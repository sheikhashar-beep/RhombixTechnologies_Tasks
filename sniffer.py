from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    print("\n=== New Packet Captured ===")

    # Check if IP layer exists
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

    # Check for TCP
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("Protocol Type: TCP")
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")

    # Check for UDP
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("Protocol Type: UDP")
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")

    # Show raw data (optional)
    if packet.haslayer("Raw"):
        print(f"Payload: {packet['Raw'].load}")

# Start sniffing
print("Starting Network Sniffer... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)