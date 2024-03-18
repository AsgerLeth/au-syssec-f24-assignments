#!/usr/bin/env python3
from scapy.all import *
import os
import fcntl
import struct
import ssl

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

IP_A = "0.0.0.0" # Listen on all interfaces
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((IP_A, PORT))

# Create a TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Configure the TUN interface
os.system("ifconfig tun0 10.8.0.1 netmask 255.255.255.0 up")

# Create UDP socket
#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# Load the server's certificate and private key
context.load_cert_chain(certfile="cert.pem")

# Wrap the server's socket with the SSL context


while True:
    # Accept a new connection
    client_sock, client_address = sock.accept()
    secure_sock = context.wrap_socket(sock, server_side=True)
    while True:
        data, (ip, port) = sock.recvfrom(2048)
        print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
        pkt = IP(data)
        print(" Inside: {} --> {}".format(pkt.src, pkt.dst))

        # Write the packet to the TUN interface
        os.write(tun, bytes(pkt))