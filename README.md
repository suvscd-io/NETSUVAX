# SCS 🐝

<div align="center">

███████  ███████  ███████           •><•
██       ██       ██                ^^v^^
███████  ██       ███████          •><•><•
      ██ ██             ██         ^^vvv^^
███████  ███████  ███████          •><•><•
                                      ^^^
    ═══ By SuvScd ═══

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](README.md)

</div>

---

## 🚀 Overview

**SCS** is a fast, professional Python CLI network scanner for cybersecurity and network administration.
It supports high-speed TCP/SYN scans, banner grabbing, multi-threading, and export to JSON/CSV.

---

## ✨ Features

- **Multi-threaded Scanning** – Fast, simultaneous port checks
- **Scan Types** – TCP Connect & SYN (stealth) scans
- **Flexible Targeting** – IPs, ranges, CIDRs, hostnames
- **Service Detection** – Service IDs & banner grabbing
- **Modern Output** – Progress bars, colored tables, summaries
- **Export Results** – JSON & CSV support
- **Configurable** – Custom timeouts, threads
- **Security-Oriented** – For authorized assessments only

---

## ⚙️ Installation

**Prerequisites:**  
- Python 3.8+
- Linux (Kali recommended)
- Root (for SYN scan)

**Clone and Install:**
```bash
git clone https://github.com/YourUsername/SCS.git
cd SCS
pip install -r requirements.txt
# (Optional) Development mode
pip install -e .
```
**Manual Dependencies:**
```bash
pip install click scapy rich
```

---

## 🏃 Quick Start

**Basic Scan:**  
```bash
python main.py scan --targets "192.168.1.1" --ports "22,80,443"
```
**Range Scan:**  
```bash
python main.py scan --targets "192.168.1.0/24" --ports "1-1000"
```
**SYN Scan (root):**  
```bash
sudo python main.py scan --targets "target.com" --ports "1-1000" --scan-type syn
```

---

## 📚 Example Usage

- **Home Network:**  
  `python main.py scan --targets "192.168.1.0/24" --ports "22,80,443"`

- **Web Server:**  
  `python main.py scan --targets "example.com" --ports "80,443,8080"`

- **Security Audit:**  
  `sudo python main.py scan --targets "target.com" --ports "1-1000" --scan-type syn`

---

## 📦 Output Formats

- **Console:** Progress bar, colored table, summary
- **JSON:**
  ```json
  [{"target": "192.168.1.1", "port": 22, "status": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.0", "timestamp": 1694123456.789}]
  ```
- **CSV:**
  ```csv
  target,port,status,service,banner,timestamp
  192.168.1.1,22,open,SSH,SSH-2.0-OpenSSH_8.0,1694123456.789
  ```

---

## 🛡️ Ethics & Security

- Only scan networks you **own** or have explicit **permission**
- Use SYN scan responsibly
- Respect network policies and rate-limit scans

---

## 🛠️ Troubleshooting

- **Missing module:**  
  `pip install -e . && PYTHONPATH=. python main.py ...`
- **SYN scan requires root:**  
  `sudo python main.py ... --scan-type syn`
- **Slow scan:**  
  `python main.py ... --timeout 0.3 --threads 300`

---

## 📄 License

MIT – see [LICENSE](LICENSE)

---

## 👤 Author

**SuvScd**

---

## ⭐ Support

If you find this tool helpful, please **star** ⭐ and share!
