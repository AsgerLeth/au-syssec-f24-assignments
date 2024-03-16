#!/usr/bin/env python3
from scapy.all import *
import os
import fcntl
import struct

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

IP_A = "0.0.0.0" # Listen on all interfaces
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

# Create a TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Configure the TUN interface
os.system("ifconfig tun0 10.8.0.1 netmask 255.255.255.0 up")

while True:
    data, (ip, port) = sock.recvfrom(2048)
    print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
    pkt = IP(data)
    print(" Inside: {} --> {}".format(pkt.src, pkt.dst))

    # Write the packet to the TUN interface
    os.write(tun, bytes(pkt))