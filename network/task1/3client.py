from scapy.all import *

def send_icmp_type_47(destination, message):
    """Send an ICMP packet of type 47 to the specified destination."""
    # Create an IP packet with the destination address
    ip = IP(dst=destination)
    # Create an ICMP packet with type 47. Code is set to 0 by default, but you can change it if needed.
    # The / operator is used to stack layers
    icmp = ICMP(type=47, code=0)
    # The payload of the ICMP packet; you can customize this as needed
    payload = Raw(load=message.encode())
    # Stack the layers and send the packet
    packet = ip/icmp/payload
    send(packet)

# Example usage
if __name__ == "__main__":
    destination = sys.argv[1]  # Replace "localhost" with the target IP address
    while True:
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        send_icmp_type_47(destination, message)
