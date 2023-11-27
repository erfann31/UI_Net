import pydivert


def send_message(message, dest_mac):
    # Create a new WinDivert instance
    with pydivert.WinDivert() as w:
        # Create a packet with the message and destination MAC address
        packet = pydivert.Packet()
        packet.payload = message.encode('utf-8')
        packet.dst_addr = dest_mac

        # Send the packet
        w.send(packet)


def receive_messages():
    # Create a new WinDivert instance
    with pydivert.WinDivert() as w:
        # Start capturing packets
        w.open()

        while True:
            # Capture the next packet
            packet = w.recv()

            # Retrieve the message and sender's MAC address
            message = packet.payload.decode('utf-8')
            sender_mac = packet.src_addr

            # Display the received message
            print(f"Received message from {sender_mac}: {message}")


def main():
    option = input("Enter '1' to send a message or '2' to receive messages: ")

    if option == '1':
        message = input("Enter your message: ")
        dest_mac = input("Enter the destination MAC address: ")
        send_message(message, dest_mac)
    elif option == '2':
        receive_messages()
    else:
        print("Invalid option!")


if __name__ == "__main__":
    main()
