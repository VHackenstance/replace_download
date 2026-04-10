#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

ack_list = []

def process_packet(packet):
    scapy_packet= IP(packet.get_payload())
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        if scapy_packet[TCP].dport == 80:
            print("HTTP Request: ")
            if ".exe" in scapy_packet[Raw].load:
                # Does not work with https, which is all sites now
                print("[+] Exe Request: ")
                # get the acknowledgement (ack) reference of the request.
                ack_list.append(scapy_packet[TCP].ack)
                print(scapy_packet.show())
                # manually initiate TCP handshake
                # some code here to replace the code
        elif scapy_packet[TCP].sport == 80:
            print("HTTP Response: ")
            # Look for the sequence of the current response is in the ack list
            if scapy_packet[TCP].sec in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing File: ")
                print(scapy_packet.show())

    packet.accept()
    return None # suppress excess packets being printed.

if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


