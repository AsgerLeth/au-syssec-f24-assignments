from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

def encrypt_payload_with_aes_gcm(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # Combine nonce, tag, and ciphertext for transmission
    return nonce + tag + ciphertext

def send_icmp_type_47(destination, message, key):
    """Send an encrypted ICMP packet of type 47 to the specified destination."""
    encrypted_message = encrypt_payload_with_aes_gcm(message, key)
    # Create and send the packet as before, but with encrypted_message
    ip = IP(dst=destination)
    icmp = ICMP(type=47, code=0)
    payload = Raw(load=encrypted_message)
    packet = ip/icmp/payload
    send(packet)

# Example usage
if __name__ == "__main__":
    destination = sys.argv[1]  # Command line argument for the destination IP
    key = get_random_bytes(16)  # Generate a new AES key for this session
    print(f"Encryption key (hex): {key.hex()}")
    while True:
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        send_icmp_type_47(destination, message, key)
