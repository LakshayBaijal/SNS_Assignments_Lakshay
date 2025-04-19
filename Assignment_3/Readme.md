# Lab Assignment 2:

## Signature and Anomaly-based Intrusion Detection and Prevention System (NIDPS)

## Team ID - 1

### Member 1

- Name: S.V. Mohit Kumar
- Roll Number: 2024201010

### Member 2

- Name: Lakshay Baijal
- Roll Number: 2024202006

Device 1 attacker -
[Screencast from 2025-04-19 23-23-41.webm](https://github.com/user-attachments/assets/7c417ae1-f4fb-4306-b196-2c2a14ffbefa)

Device 2 NIDS -


# Network Intrusion Detection System (NIDS)

This project is a Python-based Network Intrusion Detection System (NIDS) designed to detect port scanning and OS fingerprinting attacks. Using Scapy for packet sniffing and analysis, the IDS monitors live network traffic, automatically logs suspicious activities, and can block offending IP addresses using system firewall rules on Linux (using iptables) or Windows (using netsh). This tool is intended for educational, testing, and experimental purposes.

## Features

- **Packet Sniffing:**  
  Captures live packets on the network using Scapy.
- **Port Scan Detection:**  
  Detects potential port scanning by monitoring for connections to multiple ports from the same IP within a specified time window.
- **OS Fingerprinting Detection:**  
  Analyzes TCP flag variations to detect possible OS fingerprinting attempts, triggering alerts and blocking if thresholds are met.
- **IP Blocking:**  
  Automatically blocks suspicious IPs by updating system firewall rules and an internal block list.
- **Logging and Reporting:**  
  Logs intrusion events to `ids.log` and provides CLI options to view logs and generate reports.
- **Interactive CLI Interface:**  
  Offers options such as starting/stopping the IDS, viewing live traffic, managing blocked IPs, setting block methods, and more.

## CLI Interface

Once running, the IDS provides an interactive CLI with the following options:

- Start/Stop IDS:
  Toggle the packet capturing process.

- View Live Traffic:
  Monitor recent packets (live view) on the network.

- View Intrusion Logs:
  Display the contents of the log file (ids.log) with recorded intrusion events.

- Display Blocked IPs:
  List all IPs currently blocked.

- Clear Block List:
  Unblock all previously blocked IPs and clear the internal block list.

- Unblock an IP:
  Remove a specific IP address from the block list.

- Generate Report:
  Generate a summary report of the detected intrusions.

- Set Blocking Method:
  Configure the blocking method (options: internal, firewall, or both).

- Exit:
  Stop the IDS and exit the application.

#### Port Scan:

- PORT_SCAN_THRESHOLD: Number of unique ports required to trigger detection.

- PORT_SCAN_WINDOW: Time window (in seconds) for port scan analysis.

#### OS Fingerprinting:

- FINGERPRINT_THRESHOLD: Number of unique TCP flag combinations triggering detection.

- FINGERPRINT_WINDOW: Time window (in seconds) for fingerprinting analysis.

### Files:

- Log File: ids.log
  Stores detailed logs of detections.

- Block List File: blocked_ips.txt
  Persists the list of blocked IP addresses between sessions.

## Implementation

- Create Virtual Environment for Python and install

```bash

  pip install scapy argparse

```

- For Device 1

```bash
sudo python nids.py
```

- For Device 2

```bash
sudo python Attacker_simulator.py -t [IP] -a fingerprint
```

```bash
sudo python Attacker_simulator.py -t [IP] -a scan
```

- example: python3 Attacker_simulator.py -t 10.42.0.77 -a fingerprint

- if not sudo then run terminal in administrative mode
