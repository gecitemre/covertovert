import socket
import struct

from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Ether, send, sniff

"""Covert Storage Channel that exploits Protocol Field Manipulation using Reserved Flag field in IP [Code: CSC-PSV-IP-RF]"""


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

    received_message = ""

    def __init__(self):
        """
        - You can edit __init__.
        """
        super().__init__()

    def send(self, log_file_name, source, destination):
        """
        This function generates a random binary message, embeds it into the reserved flag field of the IP header, and sends it.
        source: Source IP address
        destination: Destination IP address
        """
        # Generate a random binary message
        message = self.generate_random_binary_message()

        # Convert the message to binary format
        binary_message = "".join(format(ord(char), "08b") for char in message)

        # Split the binary message into 3-bit chunks
        for i in range(0, len(binary_message), 3):
            fragment = binary_message[i : i + 3]
            reserved_flag = int(fragment, 2) << 13

            # Create the IP header with the reserved flag
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                69,  # Version and IHL
                0,  # Type of Service
                20,  # Total Length
                54321,  # Identification
                reserved_flag,  # Flags and Fragment Offset
                255,  # TTL
                socket.IPPROTO_TCP,  # Protocol
                0,  # Header Checksum
                socket.inet_aton(source),  # Source Address
                socket.inet_aton(destination),  # Destination Address
            )

            # Send the packet
            send(IP(ip_header))

    def process_packet(self, packet):
        """
        This function processes the received packet and extracts the message embedded in the reserved flag field of the IP header.
        """
        # Extract the reserved flag field
        flags_and_fragment_offset = packet[IP].flags
        reserved_flag = flags_and_fragment_offset >> 13

        # Extract the message
        self.received_message += format(reserved_flag, "03b")

    def receive(self, log_file_name, source, destination, expected_message_length=10):
        """
        This function listens for incoming packets, extracts messages embedded in the reserved flag field of the IP header, and logs the received binary message.
        source: Source IP address
        destination: Destination IP address
        expected_message_length: Length of the expected binary message
        """
        self.received_message = ""

        sniff(filter="ether", prn=self.process_packet)

        # Convert the received binary message to a string
        received_message = "".join(
            chr(int(self.received_message[i : i + 8], 2))
            for i in range(0, len(self.received_message), 8)
        )

        return received_message
