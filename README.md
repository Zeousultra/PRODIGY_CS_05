# Packet Sniffer Tool

A simple Python-based packet sniffer using the Scapy library. This tool allows you to capture network packets and log details about them, such as the source and destination IP addresses, the protocol in use (TCP, UDP, or ICMP), and more.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Examples](#examples)
- [Disclaimer](#disclaimer)
- [License](#license)

## Installation
Ensure you have Python installed on your system.

Install the Scapy library:
```bash
pip install scapy
```
Clone this repository:
```bash
git clone https://github.com/Zeousultra/Packet_Sniffer.git
cd Packet_Sniffer
```

## Usage
Run the script with the following options:
```bash
python packet_sniffer.py [--protocol tcp|udp|icmp|all] [--count COUNT] [--output FILE]
```
### Options:
| Argument | Description |
|----------|-------------|
| `--protocol` | Specify which packets to capture (TCP, UDP, ICMP, or all). Default is all. |
| `--count` | Number of packets to capture. Default is unlimited. |
| `--output` | Log output to a specified file instead of printing it to the console. |

### Example:
To capture 20 TCP packets and log the output to a file:
```bash
python packet_sniffer.py --protocol tcp --count 20 --output packet_log.txt
```

## Features
- **Protocol Filtering**: Capture specific protocols (TCP, UDP, ICMP) or all protocols.
- **Packet Logging**: Logs packets to a file or prints them to the console.
- **Packet Details**: For each packet, the tool logs:
  - Timestamp
  - Source IP and Port
  - Destination IP and Port
  - Protocol (TCP/UDP/ICMP)
- **Command-line Arguments**: Flexible usage with command-line options for packet count, protocol, and output.

## Examples
Capture 50 packets of any protocol:
```bash
python packet_sniffer.py --count 50
```
Capture only UDP packets:
```bash
python packet_sniffer.py --protocol udp --count 10
```
Log TCP packets to a file:
```bash
python packet_sniffer.py --protocol tcp --output output.log
```

## Disclaimer
This tool is meant for educational purposes only. Ensure that you have permission to sniff traffic on the network you are capturing from. Unauthorized use of this tool may be illegal and unethical.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

