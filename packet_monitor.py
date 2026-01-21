from scapy.all import *
from scapy.layers.inet import TCP, IP


def inspect(pkt):
    if pkt.haslayer(TCP):
        if pkt[TCP].dport == 80:
            print("HTTP packet detected")
        if pkt.haslayer(IP) and pkt[IP].src == "1.2.3.4":
            print("Blocked IP detected")

sniff(filter="ip", prn=inspect, store=0)
