import socket
import struct
import time

from CovertChannelBase import CovertChannelBase
from scapy.all import IP, send, sniff

BIT_NOT_RECEIVED = "2"


class MyCovertChannel(CovertChannelBase):
    received_message = ""

    def __init__(self):
        super().__init__()
        self.source = None
        self.destination = None

    def send(self, source, destination, log_file_name):
        self.source = source
        self.destination = destination

        message = self.generate_random_binary_message()
        with open(log_file_name, "w") as my_file:
            my_file.write(message)

        length = len(message)
        length_bits = format(length, "010b")
        self.send_message(length_bits)

        time.sleep(1)
        self.send_message(message)

    def send_message(self, message):
        for i, bit in enumerate(message):
            ip_packet = IP(
                src=self.source,
                dst=self.destination,
                id=i,
                flags=0b100 if bit == "1" else 0b000,
            )

            send(ip_packet, verbose=False)

    def process_packet(self, packet):
        if packet.id >= len(self.received_message):
            return

        flags = packet[IP].flags
        reserved_flag = flags & 0b100

        self.received_message[packet.id] = "1" if reserved_flag else "0"

    def sniff_packets(self, expected_length):
        self.received_message = [BIT_NOT_RECEIVED] * expected_length
        sniff(
            filter=f"ip and src {self.source} and dst {self.destination}",
            prn=self.process_packet,
            stop_filter=lambda _: BIT_NOT_RECEIVED not in self.received_message,
        )
        return "".join(self.received_message)

    def receive(self, log_file_name, source, destination):
        self.source = source
        self.destination = destination

        expected_message_length = int(self.sniff_packets(10), 2)
        message = self.sniff_packets(expected_message_length)

        with open(log_file_name, "w") as my_file:
            my_file.write(message)
        return message
