#!/usr/bin/env python3
# Rebuild
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

extensions = [".exe",".url",".zip",".pdf",".json",".md",".yml","","","",]

def process_packet(packet):
    scapy_packet= IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        if scapy_packet.haslayer(TCP):
            print("[+] Packet has layer TCP")
            if scapy_packet[TCP].dport == 80:
                print("\n\n[+] This is a HTTP Request: ")
            #     # The load is unreadable, according to internet, a TLS encryption.
            #     # However, str() cast works
            #     load = str(scapy_packet[Raw].load)
            #     print("\n[+] Load set to a string:\n")
            #     print(load)
                # Look for an .exe download, from but can update this for any download
        # elif scapy_packet[TCP].sport == 80:
        #     print("\n\n[+] This is a HTTP Response: ")
        #     print(scapy_packet.show())
        # # Do not know why as of now but OWASP Juice Shop on P:3000 is serving requests http
        # if scapy_packet[TCP].dport == 443:
        #     print("\n\n[+] This is a HTTPS Request: ")
        #     print(scapy_packet.show())
        # elif scapy_packet[TCP].sport == 443:
        #     print("\n\n[+] This is a HTTPS Response: ")
        #     print(scapy_packet.show())

    packet.accept()

if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


