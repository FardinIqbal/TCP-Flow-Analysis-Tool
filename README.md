# TCP Flow Analysis Tool

A Python-based network analysis utility for dissecting TCP flows from PCAP files. This tool leverages the `dpkt` library to parse raw packet capture data and provides in-depth flow-level metrics such as throughput, congestion behavior, window scaling, and retransmission types. Inspired by the diagnostic capabilities of tools like Wireshark and TCPDump, this project brings targeted, scriptable TCP insight to the command line.

---

## Table of Contents
- [Features](#features)
- [Dependencies](#dependencies)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Internals & Methodology](#internals--methodology)
- [Testing](#testing)
- [Customization](#customization)
- [Project Structure](#project-structure)
- [References](#references)
- [License](#license)

---

## Features

- **Automatic Flow Detection**  
  Identifies all TCP flows between predefined sender and receiver IPs using 4-tuple identifiers (src IP, src port, dst IP, dst port).

- **Connection Metadata Extraction**  
  Reports initial TCP transaction metadata after the handshake, including:
  - Sequence number
  - Acknowledgment number
  - Scaled TCP receive window size

- **Throughput Calculation**  
  Measures throughput in Mbps per flow based on total TCP-level bytes over active connection duration.

- **Congestion Window Estimation**  
  Approximates congestion window growth over the first three RTTs after connection establishment.

- **Retransmission Analysis**  
  Categorizes retransmissions as:
  - Triple duplicate ACKs
  - Timeout-based retransmissions
  - Others

- **Readable CLI Output**  
  Cleanly formatted summaries for quick inspection and debugging.

---

## Dependencies

- Python 3.x  
- `dpkt` library

Install dependencies using pip:

```bash
pip install dpkt
```

---

## Usage

```bash
python analysis_pcap_tcp.py 
```

### Example:

```bash
python analysis_pcap_tcp.py sample_traffic.pcap
```

The script is preconfigured to analyze traffic between:

- **Sender:** `130.245.145.12`
- **Receiver:** `128.208.2.198`

(These values can be changed inside the script for different datasets.)

---

## Sample Output

```
TCP FLOWS INITIATED FROM SENDER (130.245.145.12):
Number of TCP flows: 3

FLOW 1 ========================================
Source: 130.245.145.12:43498
Destination: 128.208.2.198:80

** Initial Transactions (after handshake):
  Transaction 1:
    Sequence: 705,669,103
    Ack: 1,921,750,144
    Window Size: 49,152 bytes
  Transaction 2:
    Sequence: 705,669,103
    Ack: 1,921,750,144
    Window Size: 49,152 bytes

** Congestion Window Sizes:
  Window 1: 12 packets
  Window 2: 18 packets

** Retransmission Analysis:
  Total: 3
  Triple Duplicate ACKs: 2 (66.7%)
  Timeout: 1 (33.3%)

** Performance:
  Throughput: 41.07 Mbps
  Duration: 2.010 seconds
  Total Data: 10,320,224 bytes
```

---

## Internals & Methodology

- **Parsing:** Each Ethernet frame is parsed into IP and TCP headers using `dpkt`.
- **Window Scaling:** TCP window scaling option is decoded and applied to reported window sizes.
- **Congestion Window Estimation:** Packet counts within successive RTT intervals (estimated from SYN/SYN-ACK gap) approximate congestion window growth.
- **Retransmission Detection:** Sequence number repetition is combined with RTT estimates and ACK patterns to differentiate timeout and triple-duplicate retransmissions.
- **Performance Metrics:** Calculated using TCP-level data (header + payload), not including lower-layer overhead.

---

## Testing

To inspect or verify the PCAP file contents visually, tools like [Wireshark](https://www.wireshark.org/) can be useful. The script output can be cross-validated against flow graphs, sequence number charts, and TCP stream summaries within Wireshark.

---

## Customization

To adapt this for different IPs or more dynamic filtering:

- Edit the `SENDER_IP` and `RECEIVER_IP` constants at the top of `analysis_pcap_tcp.py`.
- You can also extend the script to support dynamic flow filtering or generalize beyond two fixed endpoints.

---

## Project Structure

```
.
├── analysis_pcap_tcp.py    # Main analysis script
├── sample_traffic.pcap     # Example PCAP input (not included in repo)
└── README.md               # This file
```

---

## References

- [dpkt documentation](https://dpkt.readthedocs.io/)
- [Wireshark](https://www.wireshark.org/)
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)

---

## License

This project is for educational and diagnostic use only. No license restrictions apply, but attribution is appreciated if reused.

---
