from scapy.all import rdpcap, IP
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Measure traffic to a server in a pcap file")
    parser.add_argument('-f', '--pcap_file', type=str, help='Path to the pcap file')
    parser.add_argument('-s', '--server_ip', type=str, help='Server IP')
    parser.add_argument('-c', '--client_ip', type=str, help='Your IP')
    return parser.parse_args()


def analyze_pcap(pcap_file, client_ip, server_ip):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Initialize counters
    total_bytes_sent = 0
    total_bytes_received = 0

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            if ip_layer.src == client_ip and ip_layer.dst == server_ip:
                total_bytes_sent += len(pkt)
            elif ip_layer.src == server_ip and ip_layer.dst == client_ip:
                total_bytes_received += len(pkt)
            total_M_sent=total_bytes_sent/1000000
            total_M_received=total_bytes_received/1000000
    print(f"Total Bytes Sent to {server_ip}: {total_M_sent} Mbytes")
    print(f"Total Bytes Received from {server_ip}: {total_M_received} Mbytes")

if __name__ == '__main__':
    args = parse_args()
    analyze_pcap(args.pcap_file, args.client_ip, args.server_ip)
