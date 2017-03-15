#!/usr/bin/env python
# coding:utf-8
from scapy.all import *

"""
Find hidden wifi
"""


def printPackage(package):
    if package.haslayer(Dot11Beacon):
        addr2 = package.getlayer(Dot11).addr2
        print package.getlayer(Dot11).info
        if package.getlayer(Dot11).info == "":
            print "[802.11] : HIDDEN_WIFI -> [%s]" % (addr2)
        else:
            print "[802.11] : NORMAL_WIFI -> [%s]" % (addr2)


sniff(iface="mon0", prn=printPackage)
