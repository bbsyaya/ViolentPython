#!/usr/bin/env python
# coding:utf-8
from scapy.all import *

"""
Find hidden wifi
"""

WIFI = []


def printPackage(package):
    if package.haslayer(Dot11Beacon):
        addr2 = package.getlayer(Dot11).addr2
        if addr2 not in WIFI:
            WIFI.append(addr2)
            print "[802.11] : HIDDEN_WIFI -> [%s]" % (addr2)


sniff(iface="mon0", prn=printPackage)
