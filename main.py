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
            print("\n[+] Packet has layer TCP")
            if scapy_packet[TCP].dport == 80:
                print("[+] This is a HTTP Request: \n")
                load = str(scapy_packet[Raw].load)
                print("[+] Load set to a string:")
                # ****** This works, for online OWASP Juice Shop ******
                print(load)

            # ********** TODO
            # ONE. search HTTP load now for .exe
            # TWO. scrap but keep commented code for HTTPS
            # ********** END TODO

            # This does not work!!!!!!!!!!!!!!!!!!!!!!!!!
            # for local OWASP so giving it a miss for now.
            # elif scapy_packet[TCP].dport == 443:
            #     print("[+] This is a HTTPS Request: \n")
            #     print(scapy_packet[Raw].load)



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


