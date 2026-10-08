# 🕵️ Packet Sniffer - Python Raw Sockets

[![GitHub](https://img.shields.io/badge/github-repo-3776AB?style=for-the-badge&logo=github&logoColor=white)](https://github.com/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OS](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black")](https://img.shields.io/)
[![LAB](https://img.shields.io/badge/Security-Lab-8A2BE2?style=for-the-badge)]("https://github.com/3078756D627261/ARPScanner/")

A simple Python packet sniffer built from scratch using Linux raw sockets. This project was created as an educational exercise to understand **how network packets are structured** and **how protocols such as** `Ethernet`, `ARP`, `IPv4`, `ICMP`, `TCP`, and `UDP` work at a low level. Rather than relying on libraries such as `Scapy`, the sniffer receives raw Ethernet frames and manually parses protocol headers using `Python's socket` and `struct modules`.

---

## ⚠️ Disclaimer

> [!WARNING]
> This tool is intended for learning about computer networks, packet structures, and raw sockets. Only capture traffic on networks and interfaces you own or have explicit permission to monitor.

---

## ✨ Features

- 📡 Captures raw Ethernet frames using Linux `AF_PACKET` sockets
- 🔌 Supports selecting a network interface from the command line
- 🧩 Manually parses Ethernet headers
- 🖧 Parses ARP packets
- 🌐 Parses IPv4 headers
- 📦 Parses TCP segments
- 🚀 Parses UDP datagrams
- 📶 Parses ICMP packets
- 🎨 Colorized terminal output
- 📋 Displays decoded protocol fields in a readable format
- 🐍 Uses only Python's standard library

### Supported protocols

| Layer |	Protocol | Status
|---|---|---|
| Data Link |	Ethernet II |	✅ |
| Data Link |	ARP |	✅ |
| Network |	IPv4 |	✅ |
| Network |	ICMP |	✅ |
| Transport |	TCP |	✅ |
| Transport |	UDP |	✅ |

---

## 🧠 What You'll Learn

This project is useful for understanding what happens to network data before it reaches applications.

A simplified packet structure looks like:

```text
┌───────────────────────────────────────────────────────┐
│                    Ethernet Frame                     │
├───────────────────────────────────────────────────────┤
│ Destination MAC │ Source MAC │ EtherType │ Payload    │
└───────────────────────────────────────────────────────┘
                                             │
                    ┌─────────────────┌──────┘
                    ▼                 ▼
              ┌──────────────┐ ┌──────────────┐
              │     IPv4     │ │     ARP      │
              │     Header   │ │    Header    │
              └──────┬───────┘ └──────────────┘
                     │
          ┌──────────┼───────────┐
          ▼          ▼           ▼
       ┌─────┐    ┌─────┐    ┌──────┐
       │ TCP │    │ UDP │    │ ICMP │
       └─────┘    └─────┘    └──────┘
```

For example, when an IPv4 packet is received, the program:

Reads the Ethernet header.
  1. Checks the `EtherType`.
  2. If the EtherType is `IPv4 (0x0800)`, parses the IP header or if the EtherType is `ARP (0x806)`, parses the ARP header.
  3. Reads the IP protocol field.
  4. Determines whether the payload contains `TCP`, `UDP`, or `ICMP`.
  5. Parses the corresponding transport/network header.
  6. Prints the decoded fields.

---

## 📁 Project Structure

A minimal project layout is enough:

```text
packet-sniffer/
├── Packetsniffer.py
└── README.md
```

---

## 🏗️ How It Works

### Creating the raw socket

The sniffer creates a Linux `AF_PACKET` raw socket:

```text
socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
```

> [!IMPORTANT]
> `AF_PACKET` allows the program to operate at the data-link layer and receive Ethernet frames directly.

> [!IMPORTANT]
>`0x0003` corresponds to `ETH_P_ALL`, allowing the socket to receive Ethernet protocols rather than restricting it to a single EtherType.

### Binding to an interface

The socket is bound to the selected network interface:

```text
socket_obj.bind((iface, 0))
```

For example:

```text
eth0
wlan0
enp3s0
```

The interface can be selected using the command-line argument:

```text
-i <interface>
```

### Receiving raw frames

The main loop waits for incoming/outgoing frames:

```text
packet, _ = sniffer.recvfrom(65535)
```

The returned packet is `raw binary data`.

At this point, Python doesn't know whether the data represents `Ethernet`, `IP`, `TCP`, `UDP`, etc. The program has to interpret the bytes according to each protocol's specification.

---

## 🔬 Packet Parsing

The project uses `Python's struct` module to interpret binary data.

For example, the Ethernet header is 14 bytes:

```text
6 bytes   Destination MAC
6 bytes   Source MAC
2 bytes   EtherType
-----------------------
14 bytes  Total
```

It is parsed with:

```text
struct.unpack("!6s6sH", frame[:14])
```

The `!` means `network byte order (big-endian)`.

The program then converts the raw bytes into human-readable values such as:

```text
Destination Mac     : ff:ff:ff:ff:ff:ff
Source Mac          : 12:34:56:78:9a:bc
Protocol            : 0x800
```

---

## 📡 Protocol Detection

The Ethernet `EtherType` tells the program what protocol is contained in the payload.

Currently:

```text
0x0806 → ARP
0x0800 → IPv4
```

For IPv4 packets, the IP Protocol field is then examined:

```text
1  → ICMP
6  → TCP
17 → UDP
```

This creates a simple protocol-decoding chain:

```text
Raw Ethernet frame
        │
        ▼
 Ethernet header
        │
        ▼
    EtherType?
     /      \
   ARP       IPv4
              │
              ▼
         IPv4 header
              │
              ▼
          Protocol?
       /     |      \
     TCP    UDP     ICMP
```

---

## 📦 Example Output

A captured TCP packet may look similar to:

```text
────────────────────────────────────────────────────────────
 Ethernet Frame
────────────────────────────────────────────────────────────
  Destination Mac       : aa:bb:cc:dd:ee:ff
  Source Mac            : 11:22:33:44:55:66
  Protocol              : 0x800

────────────────────────────────────────────────────────────
 IP
────────────────────────────────────────────────────────────
  Version               : 4
  Header Length         : 20
  Ttl                   : 64
  Protocol              : 6
  Source Ip             : 192.168.1.10
  Destination Ip        : 142.250.72.14

────────────────────────────────────────────────────────────
 TCP
────────────────────────────────────────────────────────────
  Source Port           : 49152
  Destination Port      : 443
  Sequence Number       : 123456789
  Ack Number            : 987654321
  Header Length         : 20
  Flags                 : 24
```

The exact output naturally depends on the traffic being captured.

---

## ⚙️ Requirements

### Operating System

This project is designed for `Linux`.

The use of:

```text
socket.AF_PACKET
```

means it will not work unchanged on Windows or standard macOS environments.

### Python

```text
Python 3.x is required.
```

Check your version:

```text
python3 --version
```

No third-party Python packages are required.

---

## 🚀 Usage

Clone the repository:

```text
git clone https://github.com/3078756D627261/Packetsniffer.git
cd Packetsniffer
```

Run the sniffer:

```text
sudo python3 Packetsniffer.py
```

The default interface is:

```text
eth0
```

To specify another interface:

```text
sudo python3 Packetsniffer.py -i wlan0
```

Or:

```text
sudo python3 Packetsniffer.py --iface enp3s0
```

To see available command-line options:

```text
python3 Packetsniffer.py --help
```

Example:

```text
usage: Packetsniffer.py [-h] [-i IFACE]

Simple packet sniffer with RAW socket

options:
  -h, --help            show this help message and exit
  -i IFACE, --iface     Network interface (default: eth0)
```

---

## 🔐 Permissions

Raw packet capture generally requires `elevated privileges` on Linux.

For example:

```text
sudo python3 Packetsniffer.py -i eth0
```

If you receive a socket permission error, make sure the program has sufficient privileges to create and use an AF_PACKET raw socket.

---

## ⚠️ Current Limitations

This is intentionally a simple educational sniffer, not a production packet analyzer.

Some important limitations include:

- IPv4 only
- No IPv6 parsing
- No VLAN/802.1Q parsing
- Assumes a standard 14-byte Ethernet header
- TCP parsing assumes a basic TCP header layout
- Does not decode TCP flag names
- Does not parse application-layer protocols
- No packet filtering
- No packet capture/export functionality
- No PCAP support
- No checksum validation
- No fragmented IP packet reassembly
- No TCP stream reassembly
- No graceful shutdown handling
- Limited malformed-packet/error handling

These limitations are intentional opportunities for further learning and improvement.

---

## 📚 Protocol References

This project is a great opportunity to read the actual protocol specifications.

Useful standards to study include:

- Ethernet / IEEE 802.3
- ARP — RFC 826
- IPv4 — RFC 791
- ICMP — RFC 792
- TCP — RFC 9293
- UDP — RFC 768

Understanding these specifications makes the struct.unpack() calls in the code much easier to understand.











---

