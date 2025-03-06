import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Function to handle each packet
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = "-"
            dst_port = "-"
        else:
            src_port = "-"
            dst_port = "-"
        
        packet_info = f"[{timestamp}] {protocol} Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        log_packet(packet_info)

# Function to log packet details to a file or print to console
def log_packet(packet_info):
    if args.output:
        with open(args.output, "a") as log_file:
            log_file.write(packet_info + "\n")
    else:
        print(packet_info)

# Argument parser setup
parser = argparse.ArgumentParser(description="A simple packet sniffer with logging and filtering.")
parser.add_argument("--protocol", choices=["tcp", "udp", "icmp", "all"], default="all",
                    help="Filter packets by protocol (tcp, udp, icmp, or all). Default is all.")
parser.add_argument("--count", type=int, default=0, 
                    help="Number of packets to capture. Default is unlimited.")
parser.add_argument("--output", help="Log output to a file instead of printing to the console.")

args = parser.parse_args()

# Filter logic based on protocol argument
if args.protocol == "tcp":
    protocol_filter = lambda pkt: TCP in pkt
elif args.protocol == "udp":
    protocol_filter = lambda pkt: UDP in pkt
elif args.protocol == "icmp":
    protocol_filter = lambda pkt: ICMP in pkt
else:
    protocol_filter = None  # Capture all protocols if no filter is set

print("Starting Packet Sniffer... Press Ctrl+C to stop.")
if args.protocol != "all":
    print(f"Filtering by protocol: {args.protocol.upper()}")
if args.count > 0:
    print(f"Capturing {args.count} packets.")

sniff(prn=packet_callback, count=args.count if args.count > 0 else None, lfilter=protocol_filter, store=False)
