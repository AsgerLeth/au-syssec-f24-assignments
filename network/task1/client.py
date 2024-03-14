#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
from scapy.all import *

def filter(pkt):  # Filter on receipt
    global data
    print(data)
    data = pkt[Raw].load

def process(data):
    pieces = data.split(" : ")
    for key in pieces:
        # If the message contains CHATICMP
        if key == "CHATICMP":
            # Display the message
            print(data)

def input_data():
    msg = input("CHATICMP : ")
    return msg

def send_response(msg):
    # Sending the response
    send(IP(dst="192.168.43.63") / ICMP(type="echo-request", id=0x123) / Raw(load="CHATICMP : " + str(msg)), verbose=0)

def receive():
    sniff(prn=filter, filter="icmp", count=1)
    return data

def main():
    # Capturing the message
    msg = input_data()
    # Sending the response
    send_response(msg)
    print("efter send")
    # Capturing the response
    data = receive()
    print(data)
    # Processing the message
    process(data)
    # Recursive
    main()

# Initialization
main()
