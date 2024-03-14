import socket
import os
import struct
import sys
from Crypto.Cipher import AES

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

def decrypt_payload_with_aes_gcm(encrypted_message, key):
    nonce = encrypted_message[:16]
    tag = encrypted_message[16:32]
    ciphertext = encrypted_message[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode('utf-8')

def main():
    s = create_socket()
    key = bytes.fromhex(input("Enter encryption key (hex): "))  # Key shared from the client
    print("Listening for ICMP packets...")
    
    try:
        while True:
            packet, addr = s.recvfrom(1024)
            print(f"Received ICMP packet from {addr}")
            payload = extract_payload(packet)
            try:
                message = decrypt_payload_with_aes_gcm(payload, key)
                print(f"Payload: {message}")
            except Exception as e:
                print(f"Decryption failed: {e}")

    except KeyboardInterrupt:
        print("Stopping listener")
        s.close()

if __name__ == "__main__":
    main()
