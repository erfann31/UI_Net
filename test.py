import pydivert


def send_message(mac_address, message):
    with pydivert.WinDivert() as w:
        # Construct the packet
        packet = (
                b"\x00\x01\x02\x03\x04\x05" +  # Source MAC address (dummy value)
                bytes.fromhex(mac_address) +  # Destination MAC address
                b"\x00\x00\x00\x00\x00\x00\x08\x00" +  # EtherType (0x0800 for IPv4)
                b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x11" +  # IPv4 header
                b"\x00\x00\x00\x00" +  # Source IP address (dummy value)
                b"\x00\x00\x00\x00" +  # Destination IP address (dummy value)
                b"\x00\x00\x00\x00" +  # UDP header
                message.encode()  # Message data
        )

        # Send the packet
        w.send(packet)


def receive_messages():
    with pydivert.WinDivert() as w:
        for packet in w:
            # Extract the message from the packet
            message = packet[-len(packet) + 42:].decode()

            # Display the message and source MAC address
            print(f"Received Message: {message} (From: {':'.join(f'{byte:02x}' for byte in packet.source)})")


def main():
    while True:
        choice = input("Select an option (1 = Send, 2 = Receive): ")

        if choice == '1':
            mac_address = input("Enter the destination MAC address: ")
            message = input("Enter the message to send: ")
            send_message(mac_address, message)
            print("Message sent!")
        elif choice == '2':
            print("Waiting for messages...")
            receive_messages()
        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
