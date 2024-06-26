from scapy.all import IP, TCP, UDP, sniff


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Determine the protocol type
        if protocol == 6:  # TCP
            proto_type = "TCP"
        elif protocol == 17:  # UDP
            proto_type = "UDP"
        else:
            proto_type = "Other"
        
        # Print packet details
        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {proto_type}")
        
        # Display payload data
        if proto_type == "TCP" and TCP in packet:
            tcp_layer = packet[TCP]
            payload = tcp_layer.payload
            print(f"Payload: {payload}")
        elif proto_type == "UDP" and UDP in packet:
            udp_layer = packet[UDP]
            payload = udp_layer.payload
            print(f"Payload: {payload}")
        else:
            print("Payload: None or not TCP/UDP")

# Sniff packets
sniff(filter="ip", prn=packet_callback, store=0)