#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

def process_packet(packet):
    scapy_packet= IP(packet.get_payload())
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        print("Packet has Raw and TCP layers.")
        if scapy_packet[TCP].dport == 80:
            print("HTTP Request: ")
            print(scapy_packet.show())
        elif scapy_packet[TCP].sport == 80:
            print("HTTP Response: ")
            print(scapy_packet.show())

    packet.accept()
    return None # suppress excess packets being printed.

if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


