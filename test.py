from scapy.all import *
from scapy.layers.l2 import Ether

IFACE='VMware Network Adapter VMnet8'
# Define a custom protocol with necessary fields
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        StrField("text", ""),
        MACField("destination_mac", ETHER_ANY),
    ]

class PacketModel:
    def __init__(self, src, dst, packet_type, raw_load):
        self.source = src
        self.destination = dst
        self.packet_type = packet_type
        self.raw_load = raw_load


# Function to send a message
def send_message(destination_mac, message):
    packet = Ether(dst=destination_mac) / CustomProtocol(text=message, destination_mac=destination_mac)
    packet.show()
    sendp(packet, iface=IFACE)


# Function to receive and process messages
def receive_message(packet):
    if isinstance(packet.payload, Raw) and packet.payload.load.startswith(b"message:"):
        src_mac = packet.src
        dst_mac = packet.dst
        packet_type = packet.type
        raw_load = packet.load
        stored_packet = PacketModel(src_mac, dst_mac, packet_type, raw_load)

        # Accessing stored packet information
        print(f"Source MAC: {stored_packet.source}")
        print(f"Destination MAC: {stored_packet.destination}")
        print(f"Packet Type: {stored_packet.packet_type}")
        print(f"Raw Load: {stored_packet.raw_load}")


# Sniff for incoming messages
def listen_for_messages():
    while True:
        frames =sniff(iface=IFACE, prn=receive_message, count=1)
        # print(frames[0])



# Main program loop
def main():
    while True:
        choice = input("Choose 'S' to send a message or 'R' to receive messages: ")

        if choice.upper() == 'S':
            message = "message:"
            destination_mac = input("Enter the destination MAC address: ")
            message2 = input("Enter the message to send: ")
            send_message(destination_mac, message+message2)
        elif choice.upper() == 'R':
            print("Listening for messages...")
            listen_for_messages()


if __name__ == '__main__':
    main()
