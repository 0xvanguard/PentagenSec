import os
from scapy.all import Ether, IP, TCP, wrpcap

def generate_pcap(filename, count=100):
    packets = []
    for i in range(count):
        # Benign packet
        p1 = Ether()/IP(dst="1.2.3.4", src="5.6.7.8")/TCP(dport=80, sport=12345)/b"GET / HTTP/1.1\r\n"
        packets.append(p1)
        # Malicious packet that matches dummy regex: evil_pattern_1
        p2 = Ether()/IP(dst="1.2.3.4", src="5.6.7.8")/TCP(dport=80, sport=12345)/b"evil_pattern_1ABCDEFGHIJKLMNOP"
        packets.append(p2)
    
    wrpcap(filename, packets)
    print(f"Generated {len(packets)} packets in {filename}")

if __name__ == "__main__":
    os.makedirs("pcaps", exist_ok=True)
    generate_pcap("pcaps/mixed.pcap", 1000)
