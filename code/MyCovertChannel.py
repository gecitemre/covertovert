import socket
import struct

from CovertChannelBase import CovertChannelBase
from scapy.all import IP, sniff

"""Covert Storage Channel that exploits Protocol Field Manipulation using Reserved Flag field in IP [Code: CSC-PSV-IP-RF]"""


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """

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
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # Ensure the binary message is 3 bits long
        binary_message = binary_message  # [:3].zfill(3)

        for binary_message_sliced in [
            binary_message[i : i + 3] for i in range(0, len(binary_message), 3)
        ]:
            # Create a raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # IP header fields
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                69,  # Version and IHL
                0,  # Type of Service
                20,  # Total Length
                54321,  # Identification
                0,  # Flags and Fragment Offset
                255,  # TTL
                socket.IPPROTO_TCP,  # Protocol
                0,  # Header Checksum
                socket.inet_aton(source),  # Source Address
                socket.inet_aton(destination),  # Destination Address
            )

            # Embed the binary message into the reserved flag field
            reserved_flag = int(binary_message_sliced, 2) << 13
            flags_and_fragment_offset = struct.unpack("!H", ip_header[6:8])[0]
            flags_and_fragment_offset |= reserved_flag
            ip_header = (
                ip_header[:6]
                + struct.pack("!H", flags_and_fragment_offset)
                + ip_header[8:]
            )

            # Send the packet
            sock.sendto(ip_header, (destination, 0))

            # Log the sent message
            self.log_message(binary_message_sliced, log_file_name)
        print("Message sent.")

    def process_packet(self, packet):
        print("Packet received.")

    def receive(self, log_file_name, source, destination):
        """
        This function sniffs the network and receives the message embedded in the reserved flag field of the IP header.
        source: Source IP address
        destination: Destination IP address
        """

        pass
