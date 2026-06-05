#!/usr/bin/env python3
# Rebuild
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

extensions = [".exe",".url",".zip",".pdf",".json",".md",".yml","","","",]
ack_list = []

def process_packet(packet):
    scapy_packet= IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        if scapy_packet.haslayer(TCP):
            print("\n[+] Packet has layer TCP")
            if scapy_packet[TCP].dport == 80:
                print("[+] This is a HTTP Request:  ")
                if ".exe" in scapy_packet[Raw].load:
                    print("[+] Found an Exe Request:  ")
                    print("[+] Here is our Acknowledgement Number: ")
                    print(scapy_packet[TCP].ack)
                    ack_list.append(scapy_packet[TCP].ack)

            elif scapy_packet[TCP].sport == 80:
                print("[+] This is a HTTP Response: ")
                if scapy_packet[TCP].seq:
                    print("[+] Here is our Sequence Number: ")
                    print(scapy_packet[TCP].seq)
                    if scapy_packet[TCP].seq in ack_list:
                        print("[+] Replacing File: ")
                        # ********** TODO
                        # code to replace file here
                        # ********** TODO

            # NOTE TO SELF!  We do not need to make code human readable
            # **********
            # print(scapy_packet.show())
            # load = str(scapy_packet[Raw].load)
            # print("[+] Load set to a string:")
            # print(load)

            # ********** TODO
            # Test this locally on Juice Shop
            # ********** TODO
            # now I know i do not need to make code human readable
            # Cannot unencrypt load, which shows as Broken binary.
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


