from scapy.all import *
from scapy.layers.l2 import Ether

PREM = "message:"
PREA = "ack:"
IFACE = 'Local Area Connection'
ack_received = False
block_receiving = False


# Define a custom protocol with necessary fields
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        StrField("text", ""),
    ]


class PacketModel:
    def __init__(self, src, dst, packet_type, raw_load):
        self.source = src
        self.destination = dst
        self.packet_type = packet_type
        self.raw_load = raw_load


def handle_acknowledgment(packet):
    global ack_received
    if isinstance(packet.payload, Raw) and packet.payload.load.startswith(b"ack:"):
        ack_received = True
        packet.show()
        print("Acknowledgment Received")


def wait_for_acknowledgment():
    global ack_received
    timeout = 10
    start_time = time.time()
    print("Waiting for acknowledgment...")
    while not ack_received and (time.time() - start_time) < timeout:
        sniff(iface=IFACE, prn=handle_acknowledgment, count=1)


# Function to send a message
def send_message(destination_mac, pre, message, **kwargs):
    src_mac = kwargs.get('src_mac')
    # print(src_mac)
    # print(IFACE)
    packet = Ether(dst=destination_mac, src=src_mac) / CustomProtocol(text=pre + message)
    packet.show()
    sendp(packet, iface=IFACE)


# Function to receive and process messages
def receive_message(packet):
    global block_receiving
    if isinstance(packet.payload, Raw) and packet.payload.load.startswith(b"message:"):
        src_mac = packet.src
        dst_mac = packet.dst
        packet_type = packet.type
        raw_load = packet.load
        stored_packet = PacketModel(src_mac, dst_mac, packet_type, raw_load)
        print(f"Source MAC: {stored_packet.source}")
        print(f"Destination MAC: {stored_packet.destination}")
        # print(f"Packet Type: {stored_packet.packet_type}")
        # print(f"Raw Load: {stored_packet.raw_load}")
        delimiter_index = raw_load.find(b':')

        if delimiter_index != -1:
            extracted_message = raw_load[delimiter_index + 1:].split(b'\x00')[0].decode('utf-8', errors='ignore')
            print(f"Extracted message: {extracted_message}")
            send_message(stored_packet.source, PREA, extracted_message, src_mac=stored_packet.destination)
            print(f"Acknowledgment for message '{extracted_message}' sent")
            block_receiving = True



# Sniff for incoming messages
def listen_for_messages():
    global block_receiving
    while not block_receiving:
        sniff(iface=IFACE, prn=receive_message, count=1)
        # print(frames[0])


# Main program loop
def main():
    while True:
        choice = input("Choose 'S' to send a message or 'R' to receive messages (or 'Q' to quit): ")
        global ack_received, block_receiving
        if choice.upper() == 'S':
            destination_mac = input("Enter the destination MAC address: ")
            message = input("Enter the message to send: ")
            send_message(destination_mac, PREM, message)
            wait_for_acknowledgment()  # Wait for acknowledgment after sending message
            if not ack_received:
                print("No acknowledgment received.")
            ack_received = False
        elif choice.upper() == 'R':
            block_receiving = False
            print("Listening for messages...")
            listen_for_messages()
        elif choice.upper() == 'Q':
            print("Exiting the program...")
            break


if __name__ == '__main__':
    main()
