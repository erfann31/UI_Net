import scapy.all as scapy
import time

# Define custom protocol parameters
CUSTOM_PROTOCOL_TYPE = 0x1234
DESTINATION_MAC_INDEX = 1
MESSAGE_INDEX = 2

# Function to send a message
def send_message(message, destination_mac):
    # Construct custom protocol packet
    packet = scapy.Packet()
    packet.type = CUSTOM_PROTOCOL_TYPE
    packet.fields = [destination_mac, message]

    # Send the packet
    scapy.sendp(packet, iface='eth0')

# Function to receive messages
def receive_message():
    # Listen for packets with custom protocol type
    packet = scapy.sniff(filter='type ' + str(CUSTOM_PROTOCOL_TYPE), iface='eth0', count=1)[0]

    # Extract message and sender's MAC address from the packet
    message = packet.fields[MESSAGE_INDEX]
    sender_mac = packet.fields[DESTINATION_MAC_INDEX]

    # Print the received message and sender's MAC address
    print('Received message:', message)
    print('Sender MAC address:', sender_mac)

# Main program loop
while True:
    # Check if there is a message to send
    send_mode = input('Enter \'send\' to send a message or \'receive\' to wait for a message: ')

    if send_mode == 'send':
        # Get message text and destination MAC address from user
        message = input('Enter message to send: ')
        destination_mac = input('Enter destination MAC address: ')

        # Send the message
        send_message(message, destination_mac)

        # Wait for message confirmation
        print('Waiting for message confirmation...')
        while True:
            confirmation = input('Did the message arrive successfully (yes/no)? ')
            if confirmation == 'yes':
                break

    elif send_mode == 'receive':
        # Receive and display messages
        receive_message()
