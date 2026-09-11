# Port Scanner

A lightweight network port scanner written in **C++** for Linux.

This project implements several TCP and UDP scanning techniques using standard sockets and raw sockets. It is primarily intended for learning about **TCP/IP, raw packets, port scanning, checksums, and network programming**.

> **Note:** This project is intended for authorized testing and lab environments. Only scan systems and networks you have permission to test.

---

## Features

Supported scan types:

* TCP Connect Scan
* TCP SYN Scan
* UDP Scan
* TCP ACK Scan
* TCP FIN Scan
* TCP NULL Scan
* TCP XMAS Scan

The scanner can also detect the local source port used during scanning and display basic service information for detected ports.

---

## Requirements

* Linux
* C++ compiler with C++11 or newer support
* Root privileges or the required capabilities for raw sockets

For example:

```bash
g++ main.cpp -o scanner
```

Depending on the project structure, additional source files may need to be compiled together.

---

## Usage

```bash
./scanner <IP> <SCAN_TYPE> [FIRST_PORT] [LAST_PORT]
```

### Examples

TCP Connect Scan:

```bash
./scanner 127.0.0.1 tcs
```

SYN Scan:

```bash
./scanner 192.168.1.10 scs 1 1000
```

UDP Scan:

```bash
./scanner 192.168.1.10 ucs 1 1000
```

XMAS Scan:

```bash
./scanner 192.168.1.10 xmascs 1 1000
```

---

## Scan Types

| Type     | Description      |
| -------- | ---------------- |
| `tcs`    | TCP Connect Scan |
| `scs`    | TCP SYN Scan     |
| `ucs`    | UDP Scan         |
| `acs`    | TCP ACK Scan     |
| `fcs`    | TCP FIN Scan     |
| `ncs`    | TCP NULL Scan    |
| `xmascs` | TCP XMAS Scan    |

---

## TCP Connect Scan

The TCP Connect scan uses the normal TCP connection mechanism.

The scanner attempts to establish a TCP connection to each target port.

A successful connection indicates that the port is open.

```text
Client ── SYN ──> Server
Client <─ SYN/ACK ─ Server
Client ── ACK ──> Server
```

This scan is simple and reliable, but it is more noticeable than techniques that only send crafted packets.

---

## SYN Scan

The SYN scan sends a manually crafted TCP SYN packet using a raw socket.

A typical response is:

```text
SYN/ACK → Port is open
RST     → Port is closed
```

The scanner creates the IP and TCP headers manually and calculates their checksums before sending the packet.

---

## ACK Scan

The ACK scan sends a TCP packet with the ACK flag set.

Unlike SYN scanning, an ACK scan is primarily useful for determining **firewall filtering behavior**, rather than directly determining whether a service is listening.

---

## FIN / NULL / XMAS Scans

These scans use unusual TCP flag combinations.

### FIN Scan

Sends a packet with the FIN flag enabled.

### NULL Scan

Sends a TCP packet with no TCP flags enabled.

### XMAS Scan

Sends a packet with:

* FIN
* PSH
* URG

flags enabled.

### Important limitation

In the current implementation, **FIN, NULL, and XMAS scans only display ports that receive no RST response**.

Therefore, these scans should not be interpreted as providing a definitive `open` result.

For these scan types:

```text
RST response
    ↓
Port is considered closed

No response / timeout
    ↓
Port is displayed by the scanner
    ↓
Could be open or filtered
```

This behavior is intentional because a lack of response does not necessarily prove that a port is open. A firewall may simply be dropping the packet.

---

## UDP Scan

The UDP scanner sends a manually constructed UDP packet using a raw socket and waits for a response.

UDP scanning has an important limitation:

> **The current UDP implementation is designed for specific lab/test environments where a UDP server is running and is configured to respond to the scanner's packet.**

Unlike TCP, UDP does not establish a connection before sending data.

Therefore, a lack of response does **not** automatically mean that the port is closed.

For a generic UDP service:

```text
UDP packet sent
      ↓
No response
      ↓
Could be open
Could be filtered
Could simply ignore the packet
```

The current implementation works best when testing against a UDP server specifically designed to respond to the packets sent by this scanner.

For example, a custom UDP server can be created for testing:

```text
Scanner
   │
   │ UDP packet
   ▼
UDP Test Server
   │
   │ UDP response
   ▼
Scanner
```

This makes the result deterministic enough for development and debugging.

---

## Raw Sockets

Several scan types in this project use **raw sockets**.

Raw sockets allow the program to construct network packets manually instead of relying entirely on the operating system's normal TCP/IP stack.

For example, the scanner manually creates:

```text
IPv4 Header
     +
TCP Header
```

or:

```text
IPv4 Header
     +
UDP Header
```

The project therefore provides practical experience with:

* IP headers
* TCP headers
* UDP headers
* TCP flags
* Source and destination ports
* Checksums
* Raw sockets
* Packet transmission
* Packet reception

---

## Source Port

For raw scans, the scanner generates a random source port between:

```text
1024 - 65535
```

The source port is then used to match received responses with the packet sent by the scanner.

---

## Checksums

Because packets are constructed manually, the project calculates the required checksums before transmission.

Implemented checksum handling includes:

* IPv4 checksum
* TCP checksum
* UDP checksum

Incorrect checksums can cause packets to be rejected or ignored by the destination system.

---

## Project Limitations

This is a learning-focused scanner and is not intended to replace mature tools such as Nmap.

Current limitations include:

* No advanced packet retransmission system
* No sophisticated service/version detection
* Limited UDP protocol handling
* FIN/NULL/XMAS results can represent **open or filtered** states
* UDP results depend on the target application's behavior
* Raw packet handling is currently relatively basic
* Large port ranges can create many concurrent threads
* Results are currently stored in shared global containers

These limitations are expected as part of the project's current development stage.

---

## Learning Goals

The main purpose of this project is to understand how port scanners work internally rather than simply using an existing scanner.

The project covers concepts such as:

* TCP three-way handshake
* TCP flags
* UDP communication
* Raw sockets
* IPv4 packet structure
* TCP/UDP headers
* Network byte order
* Socket programming
* Non-blocking sockets
* Timeouts
* Packet filtering
* Port-state detection
* Packet checksums
* Source-port identification

---

## Disclaimer

Use this software only against systems and networks that you own or have explicit permission to test.

Unauthorized port scanning may violate organizational policies, network rules, or applicable laws.

---

## Status

This project is under active development.

The scanner is primarily being developed as a **C++ networking and cybersecurity learning project**, with the goal of understanding the implementation details behind different port-scanning techniques.
