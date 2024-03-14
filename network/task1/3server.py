import socket
import os
import struct
import sys

def create_socket():
    """Create a raw socket capable of ICMP communication."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except socket.error as msg:
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    return s

def extract_payload(packet):
    """Extract the payload from the packet."""
    # Skip IP header (20 bytes) and ICMP header (8 bytes) to get to the payload
    payload = packet[28:]
    return payload

def main():
    s = create_socket()
    print("Listening for ICMP packets...")

    try:
        while True:
            # Receive packet
            packet, addr = s.recvfrom(1024)
            print(f"Received ICMP packet from {addr}")

            # Extract the payload
            payload = extract_payload(packet)
            # Assuming the payload is a simple string, you might need to handle binary data differently
            message = payload.decode('utf-8')
            print(f"Payload: {message}")

    except KeyboardInterrupt:
        print("Stopping listener")
        s.close()

if __name__ == "__main__":
    main()
