from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
        # Check if the ICMP type is 47
        if icmp_layer.type == 47:
            print(f"Received ICMP type 47 packet from {packet[IP].src}")
            # Print payload data if any. Payload is under the Raw layer following the ICMP layer
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"Payload: {payload}")
        else:
            print(f"Received ICMP type {icmp_layer.type} packet from {packet[IP].src}")

def main():
    print("Sniffing for ICMP packets...")
    sniff(filter="icmp", prn=packet_callback)

if __name__ == "__main__":
    main()