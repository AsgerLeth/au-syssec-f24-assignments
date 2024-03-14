#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
from scapy.all import *

def filter(pkt): # Filter on reception
    global data, srcip
    srcip = pkt[IP].src  # Capture source IP address
    data = pkt[Raw].load

def process(message):
    datas = message.decode().split(" : ")
    for key in datas:
        # If the message contains CHATICMP
        if key == "CHATICMP":
            # Display the message
            print(message)

def send_response(msg):
    # Sending the response
    print(srcip)
    send(IP(dst=srcip) / ICMP(type="echo-reply", id=0x123) / Raw(load="Server : " + str(msg)), verbose=0)

def receive():
    sniff(prn=filter, filter="icmp", count=1)
    return data

def input_data():
    msg = input("Server : ")
    return msg

def main():
    # Capture the response
    data = receive()
    # Processing the message
    process(data)
    # Capture the message to send
    msg = input_data()
    # Sending the response
    send_response(msg)
    # Recursive, continue the conversation
    main()

# Initialization
main()
