# ❖ NETSUVAX ❖

<div align="center">

```
    _   _ ______ _____ _____ _    _  _    _   __   _   _ 
   | \ | |  ____|_   _/ ____| |  | || |  | |  \ \ / /  | |
   |  \| | |__    | || (___ | |  | || |  | |   \ V /   | |
   | . ` |  __|   | | \___ \| |  | || |  | |    > <    | |
   | |\  | |____ _| |_____) | |__| |\ \_/ /    / . \   |_|
   |_| \_|______|_____|_____/ \____/  \___/    /_/ \_\  (_)
```

  ====  Advanced Network Scanner By SuvScd ====

••••••••••••••••••••••••••••••••••••••••••

**NETSUVAX – A next-generation, high-performance, and beautifully designed Python network scanner built for cybersecurity professionals and extreme-scale network audits.**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey.svg)](README.md)

</div>


## 📋 Overview

**NETSUVAX** is a **next-generation CLI-based network scanning tool**. With no rigid memory caps, dynamic ThreadPool generation, and native integration with the `rich` Python library, NETSUVAX drops legacy code in favor of a sleek, rapid, and gorgeous UI designed for massive network reconnaissance arrays.

## ✨ Key Features

* 🚀 **Uncapped Concurrent Scanning** – Dynamic thread assignment prevents `MemoryError`s even on `/8` subnets
* 🔍 **Four Scan Matrices** – Support for TCP Connect, stealthy SYN scans, UDP verification, and fast Ping sweeping
* 🎯 **Dynamic Parsing** – Effortlessly map single IPs, hostnames, ranges, or deep CIDR networks
* 🏷️ **Banner Grabbing** – Extract deep meta-information instantly 
* 🌟 **Futuristic Rich GUI** – Experience glowing progress bars, summary panels, and styled report tables
* 📁 **JSON / CSV Exports** – Parse matrices seamlessly into standardized testing tools
* 🛡️ **Stealth Focused** – Silent footprint designed for authorized red-team engagements


## 🔧 Installation

### Prerequisites

* Python **3.8+**
* Linux OS (recommended: **Kali Linux**)
* Root privileges (required for **SYN scanning**)

### Install from GitHub

```bash
# Clone the repo
git clone https://github.com/suvscd-io/NETSUVAX.git
cd NETSUVAX

# Install dependencies
pip install -r requirements.txt

# Optional: install in development mode
pip install -e .
```

### Install Dependencies Manually

```bash
pip install click scapy rich
```

## 🚀 Quick Start

Once installed globally, you can run the tool using the `netsuvax` command natively from anywhere.

### Basic TCP Scan

```bash
netsuvax scan --targets "192.168.1.1" --ports "22,80,443"
```

### Fast Ping Sweep (Host Discovery)

```bash
netsuvax scan --targets "192.168.1.0/24" --scan-type ping
```

### Deep Network Range UDP Scan (requires sudo)

```bash
sudo netsuvax scan --targets "10.0.0.0/16" --scan-type udp --ports "53,161"
```

### Stealth SYN Scan (requires sudo)

```bash
sudo netsuvax scan --targets "target.com" --ports "1-1000" --scan-type syn
```

## ⚙️ Advanced Configuration Parameters

NETSUVAX is highly configurable and optimized for massive scale reconnaissance arrays. You can pass the following parameters to manually control speed, resource constraints, and data outputs:

* `--threads <INT>`: Override the default concurrent thread count (default: 200). Use `500` or `1000` for deep /16 subnet TCP scans.
* `--timeout <FLOAT>`: Connection timeout for targets on port checks (default: 0.5 seconds). Lower this heavily for dense network sweeps.
* `--scan-type <tcp|syn|udp|ping>`: Explicitly state the traversal type. Ping will disregard all port logic and execute native OS ICMP.
* `--no-banner`: Disables text-level probing on Open ports for faster throughput.
* `--verbose`: Ejects the raw exceptions during errors for runtime debugging.
* `--output-json <FILE>` / `--output-csv <FILE>`: Generates complete matrix data files at runtime.

## 📖 Example Use Cases

### 🏠 Home Network Discovery

```bash
netsuvax scan --targets "192.168.1.0/24" --ports "22,80,443,8080"
netsuvax scan --targets "192.168.1.0/24" --scan-type ping --output-json home_scan.json
```

### 🌐 Web Server Assessment

```bash
netsuvax scan --targets "example.com" --ports "80,443,8080,8443,3000,5000"
netsuvax scan --targets "webserver.com" --scan-type tcp --ports "1-10000"
```

### 🔐 Security Assessment

```bash
sudo netsuvax scan --targets "target.com" --ports "1-1000" --scan-type syn
netsuvax scan --targets "10.0.0.0/24" --ports "22,80,443" --banner --output-csv results.csv --verbose
```


## 📊 Output Formats

### Console Output

* Real-time progress bars and colored tables
* Summary statistics and status of each port

### JSON Example

```json
[
  {
    "target": "192.168.1.1",
    "port": 22,
    "status": "open",
    "service": "SSH",
    "banner": "SSH-2.0-OpenSSH_8.0",
    "timestamp": 1694123456.789
  }
]
```

### CSV Example

```csv
target,port,status,service,banner,timestamp
192.168.1.1,22,open,SSH,SSH-2.0-OpenSSH_8.0,1694123456.789
```


## 🛡️ Security & Ethics

* Only scan networks you **own** or have **explicit permission** to test
* Use stealth scans (**SYN**) only in authorized environments
* Be mindful of **network policies** and security alerts
* Rate-limit scans to avoid overloading targets


## 🔧 Troubleshooting

### Common Issues

**❌ Missing module or Externally Managed Environment Error (`PEP 668`)**

If you encounter an "externally-managed-environment" error on newer Linux distributions (like Ubuntu 23.04+ or Debian 12+), you can bypass the block safely for this tool:

```bash
pip install -e . --break-system-packages
netsuvax scan --targets "target" --ports "ports"
```

**❌ SYN scan requires root**

```bash
sudo netsuvax scan --targets "target" --ports "ports" --scan-type syn
```

**❌ Optimizing large scans**

```bash
netsuvax scan --targets "target" --ports "ports" --timeout 0.3 --threads 500 --no-banner
```


## 📄 License

MIT License – see [LICENSE](LICENSE) for details


##  Author

**SuvScd** – Creator of **NETSUVAX**


## ⭐ Support

If you find this tool helpful, **give it a star ⭐** and share with the community!
