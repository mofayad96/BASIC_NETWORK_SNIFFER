import scapy.all as scapy
from scapy.layers import http

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")

def sniffer(interface):
    print("-----------------------------------")
    print("-------Sniffer Has Started---------")
    print("-----------------------------------")
    scapy.sniff(iface=interface, store=False, prn=process)

def process(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] ", packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            request = packet[scapy.Raw].load 
            print("[*_*] ->->->->-> ", request)

# Sniffing packets
sniffer("Wi-Fi")
