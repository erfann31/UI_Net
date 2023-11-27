import socket
from datetime import datetime
import winpcapy

# Define some constants
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
PORT = 5000

def send_message(dest_mac, msg):
    """Send a message to the destination MAC address"""
    
    # Open network device for sending using Winpcap
    dev = winpcapy.open_live('eth0', 65535, 0, 100)

    # Build proprietary packet 
    packet = dest_mac + ':' + socket.gethostname() + ':' + msg 
    
    # Send packet via raw sockets
    p = dev.send(BROADCAST_MAC, socket.AF_PACKET, 0, packet)

    print(f"Sent message to {dest_mac} at {datetime.now()}")

def receive_message():
    """Listen for incoming messages"""

    # Open network device for receiving using Winpcap  
    dev = winpcapy.open_live('eth0', 65535, 1, 100)
    
    while True:
        # Read incoming packets
        (header, packet) = dev.next()

        # Extract fields from proprietary format
        src_mac, hostname, msg = packet.split(':')

        print(f"Received from {src_mac} at {datetime.now()}: {msg}")

if __name__ == '__main__':
    
    # Run in sender or receiver mode
    mode = input("Send or Receive (s/r)? ")
    
    if mode == 's':
        dest_mac = input("Destination MAC: ").upper()
        msg = input("Message: ")
        send_message(dest_mac, msg)
    
    elif mode == 'r':
        receive_message()
