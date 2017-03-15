#!/usr/bin/env python
# coding:utf-8
from scapy.all import *

"""
Find hidden wifi
"""

WIFI_MAC = []
HIDDEN_WIFI_MAC = []


def printPackage(package):
    if package.haslayer(Dot11Beacon):
        addr2 = package.getlayer(Dot11).addr2
        if addr2 not in WIFI_MAC:
            WIFI_MAC.append(addr2)
            print "[802.11] : [HIDDEN_WIFI] -> [%s]" % (addr2)
    elif package.haslayer(Dot11ProbeResp):
        addr2 = package.getlayer(Dot11).addr2
        

sniff(iface="mon0", prn=printPackage)
