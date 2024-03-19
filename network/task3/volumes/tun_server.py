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

# Our last name is g6 standing for group 6
last_name = 'g6'
prefix = last_name.encode('utf-8')[:5]  # Take first 5 characters if last name is long

# Create a TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', prefix + b'%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
print("Interface Name: {}".format(ifname_bytes.decode("UTF-8")))
# Configure the TUN interface
os.system("ifconfig g60 10.9.0.1 netmask 255.255.255.0 up") #10.8.0.1 

# Create UDP socket
#sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# Load the server's certificate and private key
context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")

# Wrap the server's socket with the SSL context
secure_sock = context.wrap_socket(sock, server_side=True)

# Start listening for connections
secure_sock.listen(5)  # Start listening for connections
print("Server is listening on {}:{}".format(IP_A, PORT))

try:
    while True:
        print("Waiting for a new connection...")
        client_sock, client_address = secure_sock.accept()
        print("Connection from: {}".format(client_address))
        try:
            while True:
                print("Waiting for data...")
                data = client_sock.recv(2048)
                if not data:
                    break  # Break the inner loop if no data received
                print("Data received from client:", data)
                #print("Data received from {}:{}".format(ip, port))
                #print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
                pkt = IP(data)
                print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
                os.write(tun, bytes(pkt))
        except Exception as e:
            print("Error while receiving data:", e)
        finally:
            # Close the client socket
            client_sock.close()
except Exception as e:
    print("Error:", e)
finally:
    # Close the SSL socket
    secure_sock.close()
