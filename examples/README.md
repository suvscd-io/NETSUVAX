# SCS 🐝

<div align="center">

███████ ███████ ███████ •><•  
██      ██   ██    ^^v^^  
███████ ██   ███████ •><•><•  
██      ██   ██    ^^vvv^^  
███████ ███████ ███████ •><•><•  
^^^  
═══ By SuvScd ═══  

••••••••••••••••••••••••••••••••••••••••••

**A fast and versatile network scanner built in Python**

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)  
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)  
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](README.md)

</div>

---

## 📋 Overview

**SCS** is a powerful, CLI-based network scanning tool designed for **cybersecurity professionals** and **network administrators**.  
It provides **TCP** and **SYN** port scanning with features such as banner grabbing, multi-threading, and real-time progress display.

---

## ✨ Features

- 🚀 **Fast Multi-threaded Scanning** – concurrent port scanning with configurable thread pools  
- 🔍 **Multiple Scan Types** – TCP Connect and SYN Stealth scanning  
- 🎯 **Flexible Target Support** – single IPs, IP ranges, CIDR networks, and hostnames  
- 🏷️ **Service Detection** – automatic service identification and banner grabbing  
- 📊 **Beautiful Output** – rich console interface with progress bars and colored tables  
- 📁 **Export Options** – JSON and CSV export capabilities  
- ⚡ **Performance Optimized** – configurable timeouts and thread limits  
- 🛡️ **Security Focused** – designed for authorized security assessments  

---

## 🔧 Installation

### Prerequisites
- Python **3.8+**
- Linux OS (recommended: **Kali Linux**)
- Root privileges (for **SYN scanning**)

### Install from GitHub
```bash
# Clone the repository
git clone https://github.com/YourUsername/SCS.git
cd SCS

# Install dependencies
pip install -r requirements.txt

# Install in development mode (optional)
pip install -e .
```

### Install Dependencies Manually
```bash
pip install click scapy rich
```

---

## 🚀 Quick Start

### Basic Scan
```bash
python main.py scan --targets "192.168.1.1" --ports "22,80,443"
```

### Scan Network Range
```bash
python main.py scan --targets "192.168.1.0/24" --ports "1-1000"
```

### Stealth SYN Scan (requires sudo)
```bash
sudo python main.py scan --targets "target.com" --ports "1-1000" --scan-type syn
```

---

## 📖 Usage Examples

### 🏠 Home Network Discovery
```bash
# Quick scan of common ports
python main.py scan --targets "192.168.1.0/24" --ports "22,80,443,8080"

# Comprehensive scan with export
python main.py scan --targets "192.168.1.0/24" --ports "1-1000" --output-json home_scan.json
```

### 🌐 Web Server Assessment
```bash
# Web services scan
python main.py scan --targets "example.com" --ports "80,443,8080,8443,3000,5000"

# Full web stack scan
python main.py scan --targets "webserver.com" --ports "21,22,25,53,80,443,993,995,3389"
```

### 🔐 Security Assessment
```bash
# Fast stealth scan
sudo python main.py scan --targets "target.com" --ports "1-1000" --scan-type syn

# Detailed scan with banner grabbing
python main.py scan --targets "10.0.0.0/24" --ports "22,80,443" --banner --output-csv results.csv
```

### ⚡ Performance Optimization
```bash
# Fast scan (low timeout, high threads)
python main.py scan --targets "target" --ports "1-1000" --timeout 0.2 --threads 500

# Thorough scan (higher timeout, banner grabbing)
python main.py scan --targets "target" --ports "1-65535" --timeout 2.0 --threads 100 --banner
```

---

## 🎛️ Command Options

| Option        | Type     | Default  | Description                        |
|---------------|----------|----------|------------------------------------|
| `--targets`   | Required | -        | Target IPs, networks, or hostnames |
| `--ports`     | Optional | 1-1024   | Ports to scan                      |
| `--scan-type` | Optional | tcp      | Scan method (`tcp` / `syn`)        |
| `--timeout`   | Optional | 0.5      | Timeout per port (0.1–10.0s)       |
| `--threads`   | Optional | 200      | Concurrent threads (1–1000)        |
| `--banner`    | Optional | True     | Service banner detection           |
| `--output-json` | Optional | -      | JSON export filename               |
| `--output-csv` | Optional | -       | CSV export filename                |

---

## 📊 Output Formats

### Console Output
- Beautiful ASCII banner with bee 🐝  
- Real-time progress bars  
- Colored results table  
- Summary statistics  

### JSON Export
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

### CSV Export
```csv
target,port,status,service,banner,timestamp
192.168.1.1,22,open,SSH,SSH-2.0-OpenSSH_8.0,1694123456.789
```

---

## 🛡️ Security & Ethics

- Only scan networks you own or have **explicit permission** to test  
- Use **stealth scan (SYN)** for authorized penetration testing  
- Be aware that scanning may **trigger security alerts**  
- Rate-limit your scans to avoid overwhelming targets  

---

## 🔧 Troubleshooting

### Common Issues

**❌ "No module named 'discn'" Error**  
```bash
# Use PYTHONPATH
PYTHONPATH=. python main.py scan --targets "target" --ports "ports"

# Or install in development mode
pip install -e .
```

**❌ "SYN scan requires root privileges"**  
```bash
sudo python main.py scan --targets "target" --ports "ports" --scan-type syn
```

**❌ Very slow scanning**  
```bash
# Reduce timeout and increase threads
python main.py scan --targets "target" --ports "ports" --timeout 0.3 --threads 300
```

---

## 📁 Project Structure
```
SCS/
├── discn/             # Main package
│   ├── __init__.py
│   ├── __main__.py    # Module entry point
│   ├── cli.py         # CLI interface and banner
│   └── scs.py         # Core scanner engine
├── main.py            # Primary entry point
├── requirements.txt   # Dependencies
├── setup.py           # Package setup
├── README.md          # This file
└── LICENSE            # MIT License
```

---

## 🗺️ Roadmap

- [ ] Add **UDP scanning**  
- [ ] Implement **OS detection**  
- [ ] Add **XML export format**  
- [ ] Web UI for scan results  
- [ ] Advanced reporting & charts  

---

## 📝 TODO

- Refactor scanning engine for better performance  
- Add automated tests (pytest)  
- Improve banner grabbing for more protocols  
- Add Docker support for easier deployment  

---

## 🤝 Contributing

Contributions are welcome!  

1. Fork the repository  
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)  
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)  
4. Push to the branch (`git push origin feature/AmazingFeature`)  
5. Open a Pull Request  

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🐝 Author

**SuvScd** – Creator of **SCS**

---

## ⭐ Support

If you found this tool helpful, please **give it a star ⭐** and share it with others!
