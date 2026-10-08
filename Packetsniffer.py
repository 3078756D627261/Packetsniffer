#! /usr/bin/python3

import socket
import struct
import argparse
import sys

# Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""
    {CYAN}{BOLD}
╭──────────────────────────────────────────╮
│           Packet Sniffer v1.0            │
╰──────────────────────────────────────────╯
    {RESET}""")

def print_fields(data):
    for key, value in data.items():
        label = key.replace("_", " ").title()
        print(f"  {label:<22}: {value}")

def print_header(title):
    print(f"{'─' * 60}")
    print(f"{GREEN}{BOLD} {title}{RESET}")
    print(f"{'─' * 60}")

def unpack_icmp(packet, ip_header_length):
    """
    !  B  B   H    H    H
    │  │  │   │    │    │
    │  │  │   │    │    └── Sequence Number    (2 bytes)
    │  │  │   │    └─────── Identifier         (2 bytes)
    │  │  │   └──────────── Checksum           (2 bytes)
    │  │  └──────────────── Code               (1 byte)
    │  └─────────────────── Type               (1 byte)
    └────────────────────── Network byte order (big-endian)
    """
    offset = 14 + ip_header_length
    icmp_header = struct.unpack("!BBHHH", packet[offset:offset + 8])
    return {
        "type": icmp_header[0],
        "code": icmp_header[1],
        "checksum": icmp_header[2],
        "identifier": icmp_header[3],
        "sequence": icmp_header[4]
    }

def unpack_udp(packet):
    """
    ! H   H   H   H
    │ │   │   │   │
    │ │   │   │   └─────────── Checksum             (2 bytes)
    │ │   │   └─────────────── Length               (2 bytes)
    │ │   └─────────────────── Destination Port     (2 bytes)
    │ └─────────────────────── Source Port          (2 bytes)
    └───────────────────────── Network byte order   (big-endian)
    """
    udp_header = struct.unpack("!HHHH", packet[34:42])
    return {
        "source_port": udp_header[0],
        "destination_port": udp_header[1],
        "length": udp_header[2],
        "checksum": udp_header[3]
    }

def unpack_tcp(packet):
    """
    ! H   H   L   L   H   H   H   H
    │ │   │   │   │   │   │   │   │
    │ │   │   │   │   │   │   │   └────────────────── Urgent Pointer        (2 byte)
    │ │   │   │   │   │   │   └────────────────────── Window Size           (2 byte)
    │ │   │   │   │   │   └────────────────────────── Checksum              (2 byte)
    │ │   │   │   │   └────────────────────────────── Data Offset + Flags   (2 byte)
    │ │   │   │   └────────────────────────────────── Acknowledgment Number (4 byte)
    │ │   │   └────────────────────────────────────── Sequence Number       (4 byte)
    │ │   └────────────────────────────────────────── Destination Port      (2 byte)
    │ └────────────────────────────────────────────── Source Port           (2 byte)
    └──────────────────────────────────────────────── Network byte order    (big-endian)
    """
    tcp_header = struct.unpack("!HHLLHHHH", packet[34:54]) # 20-bytes
    return {
        "source_port": tcp_header[0],
        "destination_port": tcp_header[1],
        "sequence_number": tcp_header[2],
        "ack_number": tcp_header[3],
        "header_length": (tcp_header[4] >> 12) * 4,
        "flags": tcp_header[5] & 0xFFF
    }

def unpack_ip(packet):
    """
    ! B  B  H   H   H   B   B   H   4s   4s
    │ │  │  │   │   │   │   │   │   │    │
    │ │  │  │   │   │   │   │   │   │    └───── Destination IP     (4 bytes)
    │ │  │  │   │   │   │   │   │   └────────── Source IP          (4 bytes)
    │ │  │  │   │   │   │   │   └────────────── Header checksum    (2 bytes)
    │ │  │  │   │   │   │   └────────────────── Protocol           (1 byte)
    │ │  │  │   │   │   └────────────────────── TTL                (1 byte)
    │ │  │  │   │   └────────────────────────── Identification     (2 bytes)
    │ │  │  │   └────────────────────────────── Total length       (2 bytes)
    │ │  │  └────────────────────────────────── Version + IHL      (1 byte)
    │ │  └───────────────────────────────────── TOS/DSCP           (1 byte)
    │ └──────────────────────────────────────── (network order)
    └────────────────────────────────────────── Network byte order (big-endian)
    """
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[14:34]) # 20-bytes
    return {
        "version": ip_header[0] >> 4,
        "header_length": (ip_header[0] & 15) * 4,
        "ttl": ip_header[5],
        "protocol": ip_header[6],
        "source_ip": ".".join(map(str, ip_header[8])),
        "destination_ip": ".".join(map(str, ip_header[9]))
    }

def unpack_arp(packet):
    """
    ! H  H  B  B  H  6s  4s  6s  4s
    │ │  │  │  │  │   │   │   │   │
    │ │  │  │  │  │   │   │   │   └─ Target IP          (4 bytes)
    │ │  │  │  │  │   │   │   └───── Target MAC         (6 bytes)
    │ │  │  │  │  │   │   └───────── Sender IP          (4 bytes)
    │ │  │  │  │  │   └───────────── Sender MAC         (6 bytes)
    │ │  │  │  │  └───────────────── Opcode             (2 bytes)
    │ │  │  │  └──────────────────── Protocol length    (1 byte)
    │ │  │  └─────────────────────── Hardware length    (1 byte)
    │ │  └────────────────────────── Protocol type      (2 bytes)
    │ └───────────────────────────── Hardware type      (2 bytes)
    └─────────────────────────────── Network byte order (big-endian)
    """
    arp_data = struct.unpack("!HHBBH6s4s6s4s", packet[14:42]) # 28-bytes
    return {
        "hardware_type": arp_data[0],
        "protocol_type": arp_data[1],
        "hardware_size": arp_data[2],
        "protocol_size": arp_data[3],
        "opcode": arp_data[4],
        "sender_mac": ":".join(f"{b:02x}" for b in arp_data[5]),
        "sender_ip": ".".join(map(str, arp_data[6])),
        "target_mac": ":".join(f"{b:02x}" for b in arp_data[7]),
        "target_ip": ".".join(map(str, arp_data[8])),
    }

def unpack_ethernet(frame):
    """
    ! 6s 6s H  
    │ │  │  │
    │ │  │  └─ Ethernet type      (2 bytes)
    │ │  └──── Source MAC         (6 bytes)
    │ └─────── Destination MAC    (6 bytes)
    └───────── Network byte order (big-endian)
    """
    destination_mac, source_mac, ether_type = struct.unpack("!6s6sH", frame[:14]) # 14-bytes

    # Return the data as a dictionary
    return {
        "destination_mac": ":".join(f"{b:02x}" for b in destination_mac),
        "source_mac": ":".join(f"{b:02x}" for b in source_mac),
        "protocol": hex(ether_type)
    }

def socket_binding(socket_obj, iface):
    try:
        # For AF_PACKET raw sockets on Linux, bind() expects the interface name, such as "eth0" or "wlan0", rather than an IP address
        # Setting it to 0 means: “Receive all Ethernet protocols” with no filtering
        socket_obj.bind((iface, 0))
    except socket.error as socket_binding_error:
        print(f"{RED}[X] Socket binding failed with error: {socket_binding_error}{RESET}")
        socket_obj.close()
        sys.exit(1)

def socket_creation():
    try:
        # Create a raw socket using the AF_PACKET family on Linux
        # AF_PACKET is a socket family used to create raw sockets that operate at the data link layer (Layer 2) of the OSI model. This allows you to directly send and receive Ethernet frames, giving you full control over the packet structure
        # socket.ntohs(0x0003) sets the protocol to ETH_P_ALL, capturing all Ethernet-based traffic
        socket_obj = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return socket_obj
    except socket.error as socket_creation_error:
        print(f"{RED}[X] Socket creation failed with error: {socket_creation_error}{RESET}")
        sys.exit(1)

def main():
    # Create an argument parser
    # ArgumentDefaultsHelpFormatter ensures default values are shown in the help text
    parser = argparse.ArgumentParser(description="Simple packet sniffer with RAW socket", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Define the command-line argument
    parser.add_argument("-i", "--iface", metavar="", default="eth0", help="Network interface")

    # Parse and use the argument
    arg = parser.parse_args()

    # Creating a raw socket
    sniffer = socket_creation()

    # Binding the socket
    socket_binding(sniffer, arg.iface)

    # Print banner
    banner()
    print(f"{CYAN}[*] Listening on {arg.iface}...{RESET}")
    print(f"{CYAN}[*] Press Ctrl+C to stop{RESET}")

    # Sniffing all incoming and outgoing packets
    while True:
        # The buffer size of 65535 is sufficient to capture full Ethernet frames
        packet, _ = sniffer.recvfrom(65535)

        # Packets are returned as raw binary data, so we’ll need to parse the headers manually
        ethernet_frame = unpack_ethernet(packet)
        print_header("Ethernet Frame")
        print_fields(ethernet_frame)

        if ethernet_frame["protocol"] == "0x806":
            arp_packet = unpack_arp(packet)
            print_header("ARP")
            print_fields(arp_packet)
        elif ethernet_frame["protocol"] == "0x800":
            ip_packet = unpack_ip(packet)
            print_header("IP")
            print_fields(ip_packet)

            # TCP
            if ip_packet["protocol"] == 6:
                tcp_segment = unpack_tcp(packet)
                print_header("TCP")
                print_fields(tcp_segment)
            # UDP
            elif ip_packet["protocol"] == 17:
                udp_segment = unpack_udp(packet)
                print_header("UDP")
                print_fields(udp_segment)
            # ICMP
            elif ip_packet["protocol"] == 1:
                icmp_packet = unpack_icmp(packet, ip_packet["header_length"])
                print_header("ICMP")
                print_fields(icmp_packet)

main()