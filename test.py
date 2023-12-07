from scapy.all import *
from scapy.layers.l2 import Ether

IFACE= 'VMware Network Adapter VMnet8'
# Define a custom protocol with necessary fields
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        ShortField("seq", 0),
        StrField("text", ""),
        MACField("destination_mac", ETHER_ANY),
        BitField("ack", 0, 1),  # Add an ACK field (1-bit long, for simplicity)
    ]

# Function to send a message
def send_message(destination_mac, message):
    # Fragment message if longer than 60 characters
    max_payload = 60
    seq = 0
    acknowledgements = {}

    while message:
        payload, message = message[:max_payload], message[max_payload:]
        packet = Ether(dst=destination_mac) / CustomProtocol(seq=seq, text=payload,
                                                             destination_mac=destination_mac)
        ack_received = False
        while not ack_received:
            packet.show()
            sendp(packet, iface=IFACE)
            # Wait for an ACK here (timeout can be adjusted as needed)
            ack_reply = sniff(iface=IFACE, filter=f"ether dst {Ether().src}",
                              prn=lambda x: acknowledgements.update({x[CustomProtocol].seq: True}), count=1, timeout=5)

            ack_received = acknowledgements.get(seq, False)
        seq += 1  # Increase the sequence number for each fragment

# Function to receive and process messages
def receive_message(packet):
    if packet.haslayer(CustomProtocol):
        custom_packet = packet[CustomProtocol]
        source_mac = packet[Ether].src
        seq = custom_packet.seq
        text = custom_packet.text
        print(f"Received message from {source_mac}: {text}")

        # Respond with an acknowledgement packet
        ack_packet = Ether(dst=source_mac) / CustomProtocol(seq=seq, text='', ack=1)
        sendp(ack_packet, iface=IFACE)

# Sniff for incoming messages including ACKs
def listen_for_messages():
    sniff(iface=IFACE, prn=receive_message, count=1)

# Main program loop
def main():
    while True:
        choice = input("Choose 'S' to send a message or 'R' to receive messages: ").upper()

        if choice == 'S':
            destination_mac = input("Enter the destination MAC address: ")
            message = input("Enter the message to send: ")
            send_message(destination_mac, message)
        elif choice == 'R':
            print("Listening for messages...")
            listen_for_messages()

if __name__ == '__main__':
    main()