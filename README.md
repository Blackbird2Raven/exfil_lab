# Dual-Stream Network Research Lab

A research tool for distinguishing between standard TCP traffic and covert exfiltration by analyzing Linux kernel signatures (Cubic/BBR congestion control algorithms).

## Overview

This lab consists of three Python modules designed to:

1. **legit_stream.py** - Send files using standard TCP/HTTP methods, allowing the Linux kernel to manage window scaling naturally
2. **stealth_exfil.py** - Implement low-and-slow exfiltration with randomized chunk sizes, jitter, and manual TCP socket manipulation
3. **capture_analysis.py** - Parse pcap files and compare TCP metrics (window size, RTT, IAT) between legitimate and stealth streams

## Security Note

**This repository is safe for public access:**
- `test_file.bin` contains only zeros (no sensitive data)
- All pcap files are excluded via `.gitignore`
- No captured network traffic is included in the repository

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Note: pyshark requires tshark (Wireshark command-line tools)
# On Ubuntu/Debian:
sudo apt-get install tshark

# On RHEL/CentOS:
sudo yum install wireshark
```

## Usage

### 1. Legitimate Stream Transfer

```bash
# Using socket method
python3 legit_stream.py <host> <port> <file> --method socket

# Using HTTP method
python3 legit_stream.py <host> <port> <file> --method http

# Example
python3 legit_stream.py 192.168.1.100 8080 large_file.bin
```

### 2. Stealth Exfiltration

```bash
# Basic usage
python3 stealth_exfil.py <host> <port> <file>

# Customize chunk size and jitter
python3 stealth_exfil.py <host> <port> <file> \
    --min-chunk 50 \
    --max-chunk 300 \
    --min-jitter 0.5 \
    --max-jitter 3.0

# Quiet mode
python3 stealth_exfil.py <host> <port> <file> --quiet
```

### 3. Capture Analysis

```bash
# Analyze all streams in pcap
python3 capture_analysis.py capture.pcap

# Analyze specific streams
python3 capture_analysis.py capture.pcap --streams 0 1

# Compare multiple streams
python3 capture_analysis.py capture.pcap --streams 0 1 --compare

# Apply Wireshark filter
python3 capture_analysis.py capture.pcap --filter "tcp.port == 8080"

# Export to JSON
python3 capture_analysis.py capture.pcap --json results.json
```

## Example Workflow

### Step 1: Start Test Server

```bash
# Start the test server to receive data
python3 test_server.py --host 0.0.0.0 --port 8080
```

### Step 2: Start Packet Capture

```bash
# On the receiving end or network tap
sudo tcpdump -i any -w capture.pcap 'port 8080'
```

### Step 3: Run Legitimate Transfer

```bash
# Using localhost (for local testing)
python3 legit_stream.py 127.0.0.1 8080 test_file.bin

# OR using network IP (detected: 172.16.85.132)
python3 legit_stream.py 172.16.85.132 8080 test_file.bin
```

### Step 4: Run Stealth Exfiltration

```bash
# Using localhost
python3 stealth_exfil.py 127.0.0.1 8080 test_file.bin

# OR using network IP
python3 stealth_exfil.py 172.16.85.132 8080 test_file.bin
```

### Step 4: Analyze and Compare

```bash
# Stop tcpdump (Ctrl+C)

# Analyze both streams
python3 capture_analysis.py capture.pcap --streams 0 1 --compare --json comparison.json
```

## Key Metrics Analyzed

- **TCP Window Size Evolution**: How the kernel adjusts window size based on congestion control
- **Round Trip Time (RTT)**: Latency measurements between packets
- **Inter-arrival Time (IAT)**: Time between consecutive packets
- **Packet Size Distribution**: Statistical analysis of packet sizes

## Expected Differences

### Legitimate Stream
- Consistent window size scaling (kernel-managed)
- Predictable IAT patterns
- Larger average packet sizes
- Lower IAT variance

### Stealth Exfiltration
- Irregular window size patterns (manual socket manipulation)
- High IAT variance (randomized jitter)
- Smaller, variable packet sizes
- Higher coefficient of variation in metrics

## Technical Details

### TCP Socket Options Used

**stealth_exfil.py** manipulates:
- `TCP_NODELAY`: Disables Nagle's algorithm for immediate sends
- `SO_SNDBUF` / `SO_RCVBUF`: Smaller buffer sizes to force frequent sends
- `TCP_CORK`: Toggled to control batching (if available)

### Kernel Congestion Control

The legitimate stream allows the kernel's congestion control algorithm (Cubic or BBR) to:
- Automatically adjust window sizes
- Optimize throughput based on network conditions
- Implement standard TCP flow control

## Additional Tools

### test_server.py
Simple TCP server for receiving test data. Useful for local testing without setting up external servers.

```bash
python3 test_server.py --host 0.0.0.0 --port 8080
```

See `network_config.md` for detected network interfaces and IP addresses.

## Requirements

- Python 3.7+
- pyshark
- tshark (Wireshark command-line tools)
- Root/sudo access for packet capture (optional)

## Author

Senior Detection Engineer & Linux Kernel Specialist

## License

For research and educational purposes.
