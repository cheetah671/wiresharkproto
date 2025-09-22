# C-Shark: The Terminal Packet Sniffer

🦈 Welcome to the C-Shark Division! A terminal-based packet sniffer that captures and analyzes network traffic in real-time.

## Features

- **Interface Discovery**: Automatically detects and lists all available network interfaces
- **Live Packet Capture**: Real-time packet sniffing with detailed layer-by-layer analysis
- **Protocol Support**: Supports IPv4, IPv6, ARP, TCP, UDP, HTTP, HTTPS, DNS
- **Filtering**: Filter packets by protocol (HTTP, HTTPS, DNS, ARP, TCP, UDP)
- **Packet Storage**: Stores captured packets for later inspection
- **Detailed Analysis**: In-depth packet inspection with hex dumps and header analysis
- **Graceful Controls**: Ctrl+C to stop capture, Ctrl+D to exit

## Requirements

- Linux system with root privileges
- libpcap development library
- GCC compiler

## Installation

1. Install dependencies:
```bash
make install
```

2. Compile the project:
```bash
make
```

3. Run the sniffer (requires root privileges):
```bash
sudo ./cshark
```

## Usage

### Phase 1: Interface Selection
- The program will automatically scan and display available network interfaces
- Select the interface you want to monitor (e.g., wlan0 for wireless, eth0 for ethernet)

### Phase 2: Main Menu Options

1. **Start Sniffing (All Packets)**: Captures all packets on the selected interface
2. **Start Sniffing (With Filters)**: Captures packets matching specific criteria:
   - HTTP (port 80)
   - HTTPS (port 443)
   - DNS (port 53)
   - ARP
   - TCP
   - UDP
3. **Inspect Last Session**: Review previously captured packets in detail
4. **Exit C-Shark**: Clean exit

### Phase 3: Packet Analysis

For each captured packet, C-Shark displays:

#### Layer 2 (Ethernet):
- Source and Destination MAC addresses
- EtherType (IPv4, IPv6, ARP)

#### Layer 3 (Network):
- **IPv4**: Source/Dest IP, Protocol, TTL, Packet ID, Total Length, Header Length, Flags
- **IPv6**: Source/Dest IP, Next Header, Hop Limit, Traffic Class, Flow Label, Payload Length
- **ARP**: Operation type, Sender/Target IP and MAC addresses, Hardware/Protocol info

#### Layer 4 (Transport):
- **TCP**: Source/Dest ports, Sequence/ACK numbers, Flags, Window size, Checksum, Header length
- **UDP**: Source/Dest ports, Length, Checksum

#### Layer 7 (Application):
- Protocol identification (HTTP, HTTPS, DNS)
- Payload length and hex dump (first 64 bytes)

### Phase 4: Controls

- **Ctrl+C**: Stop current capture and return to main menu
- **Ctrl+D**: Exit the application
- **Packet Storage**: Up to 10,000 packets stored per session
- **Memory Management**: Automatic cleanup between sessions

## Example Output

```
[C-Shark] The Command-Line Packet Predator
==============================================
[C-Shark] Searching for available interfaces... Found!

1. wlan0
2. any (Pseudo-device that captures on all interfaces)
3. lo
4. docker0

Select an interface to sniff (1-4): 1

[C-Shark] Interface 'wlan0' selected. What's next?

1. Start Sniffing (All Packets)
2. Start Sniffing (With Filters)
3. Inspect Last Session
4. Exit C-Shark

Enter your choice: 1

-----------------------------------------
Packet #1 | Timestamp: 1757370992.553060 | Length: 66 bytes
L2 (Ethernet): Dst MAC: E6:51:4A:2D:B0:F9 | Src MAC: B4:8C:9D:5D:86:A1 |
EtherType: IPv4 (0x0800)
L3 (IPv4): Src IP: 34.107.221.82 | Dst IP: 10.2.130.118 | Protocol: TCP (6) |
TTL: 118
ID: 0xA664 | Total Length: 52 | Header Length: 20 bytes
L4 (TCP): Src Port: 443 (HTTPS) | Dst Port: 35554 | Seq: 1490828286 | Ack: 4154012308 | Flags: [ACK]
Window: 1001 | Checksum: 0x32FA | Header Length: 20 bytes
L7 (Payload): Identified as HTTPS/TLS on port 443 - 32 bytes
Data (first 32 bytes):
17 03 03 00 1B 00 00 00 00 00 00 00 01 5E B6 F2 .............^..
6B C4 E7 C8 E1 8A 9B 37 8C F4 79 CD BE 75 42 DB k......7..y..uB.
```

## Technical Details

### Dependencies
- `libpcap`: Low-level packet capture library
- Standard C networking headers for protocol parsing

### Architecture
- Modular design with separate functions for each protocol layer
- Memory-efficient packet storage with automatic cleanup
- Signal handling for graceful interruption

### Security Notes
- Requires root privileges for packet capture
- Read-only operation - no packet injection or modification
- Designed for network monitoring and analysis only

## Troubleshooting

1. **Permission denied**: Run with `sudo`
2. **libpcap not found**: Install with `make install`
3. **No interfaces found**: Check network configuration
4. **Compilation errors**: Ensure GCC and development headers are installed

## License

This project is part of an educational assignment and follows academic guidelines.