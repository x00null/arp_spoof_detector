#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_package)


def process_sniffed_package(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        real_mac = scan(packet[scapy.ARP].psrc)
        response_mac = packet[scapy.ARP].hwsrc

        try:
            if real_mac == response_mac:
                print("[+] Warning You're Under Attack...!!!!")

        except IndexError:
            pass


sniff("eth0")
