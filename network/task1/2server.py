# server.py

from scapy.all import *
from cryptography.fernet import Fernet

# The pre-shared symmetric key for encryption and decryption
key = b'your_preshared_key_here'
#cipher_suite = Fernet(key)

def filter(pkt):
    print(pkt)
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 47 and pkt.haslayer(Raw):
        # Decrypt the message
        #decrypted_message = cipher_suite.decrypt(pkt[Raw].load)
        decrypted_message = pkt[Raw].load
        print(f"Received message: {decrypted_message.decode()}")

def main():
    print("Listening for encrypted ICMP packets...")
    sniff(prn=filter, filter="icmp", count=0)  # count=0 for infinite sniffing

if __name__ == "__main__":
    main()
