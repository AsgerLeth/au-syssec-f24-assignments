#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *
import ssl # for wrapping the socket

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)

# Our last name is g6 standing for group 6
last_name = 'g6'
prefix = last_name.encode('utf-8')[:5]  # Take first 5 characters if last name is long
ifr = struct.pack('16sH', prefix + b'%d', IFF_TUN | IFF_NO_PI)

ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

SERVER_IP   = "10.9.0.11"
SERVER_PORT = 9090

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

# Load the trusted CA certificates
context.load_verify_locations('server-cert.pem')

# Create a secure (SSL/TLS) socket
secure_sock = context.wrap_socket(sock, server_hostname=SERVER_IP)

# Connect to the server
secure_sock.connect((SERVER_IP, SERVER_PORT))

while True:
   # Get a packet from the tun interface
   print("Waiting for packet from tun interface")
   packet = os.read(tun, 2048)
   print("Packet received from tun interface", packet)
   if packet:
      # Send the packet via the secure tunnel
      secure_sock.sendall(packet)
      print("Packet sent to the server", packet)