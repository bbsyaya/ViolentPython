#!/usr/bin/env python
# coding:utf-8
from scapy.all import *

"""
Get Wifi Probe Request info
"""


def printPackage(package):
    if package.haslayer(Dot11ProbeReq):
        addr2 = package.getlayer(Dot11).addr2
        netName = package.getlayer(Dot11ProbeReq).info
        if netName == "":
            print "[802.11] : ProbeReq -> [HIDDEN_WIFI] -> [%s]" % (addr2)
        else:
            print "[802.11] : ProbeReq -> [%s] -> [%s]" % (netName, addr2)


sniff(iface="mon0", prn=printPackage)
