# client.py

import sys
from scapy.all import *
from cryptography.fernet import Fernet

# The pre-shared symmetric key for encryption
key = b'your_preshared_key_here'
#cipher_suite = Fernet(key)

def send_encrypted_message(dst_ip, message):
    # Encrypt the message
    #encrypted_message = cipher_suite.encrypt(message.encode())
    encrypted_message = message
    # Send an ICMP packet with type 47 containing the encrypted message
    send(IP(dst="172.0.0.1")/ICMP(type=47)/Raw(load=encrypted_message), verbose=0)
    print(f"Sent encrypted message: {message}" )

def main():
    if len(sys.argv) != 2:
        print("Usage: client.py <destination_ip>")
        sys.exit(1)

    dst_ip = sys.argv[1]

    while True:
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        send_encrypted_message(dst_ip, message)

if __name__ == "__main__":
    main()
