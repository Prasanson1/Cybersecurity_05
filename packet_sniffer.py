from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime
import logging
# Configure logging
logging.basicConfig(filename='packet_logs.txt', level=logging.INFO, format='%(asctime)s %(message)s')

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        protocol_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Other"
        
        log_entry = f"Timestamp: {datetime.datetime.now()} | Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol_name}"
        print(log_entry)
        logging.info(log_entry)
        
        if Raw in packet:
            payload = packet[Raw].load
            logging.info(f"Payload: {payload}")
        
        analyze_packet(ip_src, ip_dst, protocol_name, packet)

def analyze_packet(ip_src, ip_dst, protocol, packet):
    if protocol == "TCP" and packet[TCP].flags == "S":
        alert = f"Possible SYN flood attack detected from {ip_src} to {ip_dst}"
        print(alert)
        logging.warning(alert)
    
    if Raw in packet and len(packet[Raw].load) > 1000:
        alert = f"Unusually large payload detected from {ip_src} to {ip_dst}"
        print(alert)
        logging.warning(alert)

sniff(filter="ip", prn=packet_callback, store=0)
