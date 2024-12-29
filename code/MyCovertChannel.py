import socket
import struct
import time

from CovertChannelBase import CovertChannelBase
from scapy.all import IP, sniff

BIT_NOT_RECEIVED = "2"


class MyCovertChannel(CovertChannelBase):
    # Covert Storage Channel that exploits Protocol Field Manipulation using Reserved Flag field in IP [Code: CSC-PSV-IP-RF]
    received_message = ""

    def __init__(self):
        super().__init__()
        self.source = None
        self.destination = None

    # Send creates a message and stores it in out logfile. We also calculate the time to send one packet and the message is sent. The send_message
    # function calls the function send. Send_message actually encrypts the message and creates a packet and uses the send function to send that packet.
    def send(self, source, destination, log_file_name, min_length=50, max_length=100):
        self.source = source
        self.destination = destination

        message = self.generate_random_binary_message_with_logging(
            log_file_name, min_length, max_length
        )

        start_time = time.time()
        self.send_message(message)
        end_time = time.time()
        print(f"Time elapsed: {end_time - start_time}")

    def send_message(self, message):
        for i, bit in enumerate(message):
            reserved_flag = bit == "1"
            if i % 2 == 0:
                reserved_flag = (
                    not reserved_flag
                )  # For encryption, if i is even, reverse the reserved flag
            ip_packet = IP(
                src=self.source,
                dst=self.destination,
                id=i,
                flags=0b100 if reserved_flag else 0b000,
            )

            super().send(ip_packet)

    def process_packet(self, packet):
        if packet.id >= 800:
            return

        flags = packet[IP].flags
        reserved_flag = flags & 0b100
        if packet.id % 2 == 0:
            reserved_flag = (
                not reserved_flag
            )  # For decryption, if i is even, reverse the reserved flag

        if len(self.received_message) <= packet.id:
            current_bytes = len(self.received_message) // 8
            target_bytes = packet.id // 8
            self.received_message += [
                BIT_NOT_RECEIVED * (target_bytes - current_bytes + 1)
            ] * 8

        self.received_message[packet.id] = "1" if reserved_flag else "0"

    def sniff_packets(self):
        def stop_filter(packet):
            return "".join(
                self.received_message[len(self.received_message) - 8 :]
            ) == format(ord("."), "08b")

        sniff(
            filter=f"ip and src {self.source} and dst {self.destination}",
            prn=self.process_packet,
            stop_filter=stop_filter,
        )
        return "".join(self.received_message)

    def convert_binary_message_to_string(self, message):
        return "".join(
            self.convert_eight_bits_to_character(message[i : i + 8])
            for i in range(0, len(message), 8)
        )

    # Receive function receives a packet uses sniff_packets, Sniff_packet and Process_packet are used to receive and decrypt the packets
    # The binary message is then decoded to the actual string message
    def receive(self, log_file_name, source, destination):
        self.source = source
        self.destination = destination
        self.received_message = [BIT_NOT_RECEIVED] * 8
        message = self.sniff_packets()
        decoded = self.convert_binary_message_to_string(message)
        self.log_message(decoded, log_file_name)
