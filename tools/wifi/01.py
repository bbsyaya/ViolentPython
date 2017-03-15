#!/usr/bin/env python
# coding:utf-8
from scapy.all import *

"""
Get Wifi Probe Request info
"""


def printPackage(package):
    if package.haslayer(Dot11ProbeReq):
        netName = package.getlayer(Dot11ProbeReq).info
        if netName != "":
            print "[802.11] : ProbeReq -> [%s]" % (netName)


sniff(iface="mon0", prn=printPackage)
