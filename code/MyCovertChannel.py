import socket
import struct
import time

from CovertChannelBase import CovertChannelBase
from scapy.all import IP, send, sniff

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

    def send(self, source, destination, log_file_name):
        """
        This function generates a random binary message, embeds it into the reserved flag field of the IP header, and sends it.
        source: Source IP address
        destination: Destination IP address
        """
        message = self.generate_random_binary_message()
        with open(log_file_name, "w") as my_file:
            my_file.write(message)

        # Send the length of the message using 10 bits
        length = len(message)
        length_bits = format(length, "010b")
        self.send_message(length_bits, source, destination)

        time.sleep(1)
        self.send_message(message, source, destination)

    def send_message(self, message, source, destination):
        """
        This function embeds the given message into the reserved flag field of the IP header and sends it.
        source: Source IP address
        destination: Destination IP address
        message: Message to be sent
        """
        for i, bit in enumerate(message):
            ip_packet = IP(
                src=source,
                dst=destination,
                id=i,
                flags=0b100 if bit == "1" else 0b000,
            )

            send(ip_packet, verbose=False)

    def process_packet(self, packet):
        """
        This function processes the received packet and extracts the message embedded in the reserved flag field of the IP header.
        """
        if packet.id >= len(self.received_message):
            return
        # Extract the reserved flag field
        flags = packet[IP].flags

        # Extract the 3rd bit of the reserved flag field
        reserved_flag = flags & 0b100

        self.received_message[packet.id] = "1" if reserved_flag else "0"

    def receive(self, log_file_name, source, destination):
        """
        This function listens for incoming packets, extracts messages embedded in the reserved flag field of the IP header, and logs the received binary message.
        source: Source IP address
        destination: Destination IP address
        """
        self.received_message = [-1] * 10

        sniff(
            filter=f"ip and src {source} and dst {destination}",
            prn=self.process_packet,
            stop_filter=lambda _: all(bit != -1 for bit in self.received_message),
        )
        expected_message_length = 0
        for bit in self.received_message:
            expected_message_length = (expected_message_length << 1) | int(bit)
        self.received_message = [-1] * expected_message_length

        sniff(
            filter=f"ip and src {source} and dst {destination}",
            prn=self.process_packet,
            stop_filter=lambda _: all(bit != -1 for bit in self.received_message),
        )

        with open(log_file_name, "w") as my_file:
            my_file.write("".join(self.received_message))
        return self.received_message
