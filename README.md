# SCS 🐝

<div align="center">

```
 ______ 
      .-'      `-.
     /            \
    |,  .-.  .-.  ,|
    | )(_o/  \o_)( |
    |/     /\     \|
    (_     ^^     _)
     \__|IIIIII|__/
      | \IIIIII/ |
      \          /
       `--------`
```

  By SuvScd

••••••••••••••••••••••••••••••••••••••••••

**SCS 🐝 – A fast, versatile, and professional Python-based network scanner for cybersecurity professionals and network administrators. Supports TCP/SYN scans, banner grabbing, multi-threading, and more.**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](README.md)

</div>


## 📋 Overview

**SCS** is a **powerful CLI-based network scanning tool** designed for cybersecurity enthusiasts, penetration testers, and network administrators.
It allows **fast TCP and SYN port scanning** with features like **banner grabbing, multi-threading, real-time progress display**, and **exportable results**.

## ✨ Key Features

* 🚀 **High-Speed Multi-threaded Scanning** – scan multiple ports simultaneously
* 🔍 **Multiple Scan Types** – TCP Connect and SYN stealth scans
* 🎯 **Flexible Targets** – single IPs, IP ranges, CIDR networks, and hostnames
* 🏷️ **Automatic Service Detection** – identify services and grab banners
* 📊 **Beautiful Console Output** – progress bars, colored tables, and summaries
* 📁 **Export Options** – save results in JSON or CSV
* ⚡ **Optimized Performance** – configurable timeouts and threads
* 🛡️ **Security-Oriented** – designed for authorized network assessments


## 🔧 Installation

### Prerequisites

* Python **3.8+**
* Linux OS (recommended: **Kali Linux**)
* Root privileges (required for **SYN scanning**)

### Install from GitHub

```bash
# Clone the repo
git clone https://github.com/YourUsername/SCS.git
cd SCS

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

### Basic Scan

```bash
python main.py scan --targets "192.168.1.1" --ports "22,80,443"
```

### Network Range Scan

```bash
python main.py scan --targets "192.168.1.0/24" --ports "1-1000"
```

### Stealth SYN Scan (requires sudo)

```bash
sudo python main.py scan --targets "target.com" --ports "1-1000" --scan-type syn
```


## 📖 Example Use Cases

### 🏠 Home Network Discovery

```bash
python main.py scan --targets "192.168.1.0/24" --ports "22,80,443,8080"
python main.py scan --targets "192.168.1.0/24" --ports "1-1000" --output-json home_scan.json
```

### 🌐 Web Server Assessment

```bash
python main.py scan --targets "example.com" --ports "80,443,8080,8443,3000,5000"
python main.py scan --targets "webserver.com" --ports "21,22,25,53,80,443,993,995,3389"
```

### 🔐 Security Assessment

```bash
sudo python main.py scan --targets "target.com" --ports "1-1000" --scan-type syn
python main.py scan --targets "10.0.0.0/24" --ports "22,80,443" --banner --output-csv results.csv
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

**❌ Missing module**

```bash
pip install -e .
PYTHONPATH=. python main.py scan --targets "target" --ports "ports"
```

**❌ SYN scan requires root**

```bash
sudo python main.py scan --targets "target" --ports "ports" --scan-type syn
```

**❌ Slow scanning**

```bash
python main.py scan --targets "target" --ports "ports" --timeout 0.3 --threads 300
```

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## 📄 License

MIT License – see [LICENSE](LICENSE) for details


## 🐝 Author

**SuvScd** – Creator of **SCS**


## ⭐ Support

If you find this tool helpful, **give it a star ⭐** and share with the community!
