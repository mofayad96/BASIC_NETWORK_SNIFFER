import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")
            # tcp packets
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")

            # If the packet has raw data 
            if packet.haslayer(scapy.Raw):
                raw_data = packet[scapy.Raw].load
                print(f"Raw Data: {raw_data}")


print("network traffic")
scapy.sniff(iface="Wi-Fi", store=False, prn=packet_callback)
