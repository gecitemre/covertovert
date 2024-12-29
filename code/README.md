# Covert Storage Channel that exploits Protocol Field Manipulation using Reserved Flag field in IP [Code: CSC-PSV-IP-RF]

## Description
This project implements a covert storage channel that exploits protocol field manipulation using the reserved flag field in the IP header. The channel allows for the transmission of binary messages by embedding bits into the reserved flag field of IP packets. The channel also uses a predefined encryption protocol to ensure that the transmitted messages are secure. This protocol negates the bit if the id field of the IP packet is even and keeps the bit if the id field is odd. The channel has a capacity of 3200 bits per second.
The descriptions of the send and receive functions are in the MyCovertChannel.py.

## Capacity
This channel has a channel capacity of 3200 bits per second.