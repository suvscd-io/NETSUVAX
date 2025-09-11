# 🚀 SCS – Supercharged Concurrent Scanner

SCS is a modern, high-performance network scanner written in Python by suvscd. This README provides a comprehensive guide to installing, using, tuning, and extending SCS. It covers library usage, async usage, SYN scans with scapy, exports (JSON/CSV/SQLite), CLI integration tips, advanced tuning, troubleshooting, development notes, and contribution guidelines.

---

## 📌 Summary

SCS (Supercharged Concurrent Scanner) is designed for security engineers, system administrators, and researchers who need a flexible, scriptable scanner that can run from Python code. It focuses on:

- Fast async TCP scanning (asyncio-based connect scans)
- Optional SYN (stealth) scanning via scapy (requires root/administrator privileges)
- Basic UDP probes (best-effort)
- Banner grabbing to identify services
- Exporting results to JSON, CSV, and SQLite
- A beautiful terminal UI using rich (progress and tables)

This README is written by the tool author, suvscd. For the most accurate and up-to-date details, inspect the code at discn/scs.py.

---

## ✨ Highlights / Features

- ⚡ Async TCP connect scanning (high concurrency)
- 🕵️ SYN stealth scan (Scapy) for low-level TCP handshake inspection
- 📡 UDP probe for basic UDP service detection
- 🏷️ Banner grabbing with retries and HTTP probe
- ⏱️ Configurable timeouts, retries, concurrency, and rate limits
- 📦 Export to JSON / CSV / SQLite (built-in exporter)
- 📊 Rich progress bar and results table using rich
- 🌐 Flexible target parsing: single host, hostname, CIDR, IP ranges
- 🔢 Flexible port parsing: single ports, comma lists, ranges (with safety limits)

---

## 📦 Requirements

- Python 3.8+
- pip packages: scapy, rich

Install the runtime requirements:

```bash
pip install scapy rich
```

Notes:
- scapy often needs system-level capabilities to use raw sockets; on Linux, run as root for SYN scans.
- If you don't need SYN scans, SCS works fine with regular TCP connect scans as a normal user.

---

## 🔧 Installation

Clone the repo and install dependencies (optional virtualenv recommended):

```bash
git clone https://github.com/suvscd-io/SCS.git
cd SCS
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # if provided, otherwise pip install scapy rich
```

---

## 🧭 Quick Start (Examples)

Library usage (synchronous wrapper, ideal for scripts):

```python
from discn.scs import NetworkScanner

scanner = NetworkScanner(
    targets="scanme.nmap.org",  # hostnames, IPs, CIDR, or ranges supported
    ports="22,80,443",          # comma-separated ports or ranges like 1-1024
    scan_type="tcp",            # 'tcp' or 'syn'
    timeout=1.0,
    concurrency=200,
    banner_grabbing=True,
    retries=1
)
results = scanner.run_scan_cli()  # returns results and prints a table
scanner.export_json("results.json")
```

Async usage (high-throughput scanning programmatically):

```python
import asyncio
from discn.scs import NetworkScanner

async def main():
    scanner = NetworkScanner(targets="203.0.113.0/30", ports="80,443", scan_type="tcp", concurrency=500, timeout=0.5)
    results = await scanner.run_scan_async()
    scanner.export_csv("async_results.csv")

asyncio.run(main())
```

SYN stealth scan (requires root/admin):

```python
scanner = NetworkScanner(targets="192.168.1.0/28", ports="1-1024", scan_type="syn", concurrency=100)
results = scanner.run_scan_cli()
```

UDP best-effort probe (note: UDP detection is inherently unreliable without privileged raw sockets):

```python
scanner = NetworkScanner(targets="192.168.1.5", ports="161,69", scan_type="tcp", udp=True)
results = scanner.run_scan_cli()
```

---

## 🧾 API Reference (Key methods & constructor)

Constructor signature (conceptual):

```python
NetworkScanner(
    targets: str,            # e.g. "10.0.0.1", "example.com", "192.168.0.0/24", "10.0.0.1-10.0.0.255"
    ports: str,              # e.g. "22,80,443", "1-1024"
    scan_type: str = "tcp",# 'tcp' (connect scan) or 'syn'
    timeout: float = 0.5,
    concurrency: int = 500,
    banner_grabbing: bool = True,
    retries: int = 1,
    udp: bool = False,
    rate_limit: Optional[float] = None,  # ops per second
    logfile: Optional[str] = None,
    sqlite_db: Optional[str] = None
)
```

Important methods:

- .run_scan_cli() -> List[dict]
  - Synchronous entrypoint. For TCP scans it will run the async engine under the hood; for SYN scans it will run the scapy-based scan synchronously.
- .run_scan_async() -> Coroutine[List[dict]]
  - Use this in your asyncio code to run high-performance scans directly.
- .export_json(path)
- .export_csv(path)
- Passing sqlite_db to constructor writes results to SQLite on completion.

Result object format (each open port):

```json
{
  "target": "192.0.2.10",
  "port": 80,
  "status": "open",
  "service": "HTTP",
  "banner": "HTTP/1.1 200 OK\n...",
  "timestamp": 1690000000.0
}
```

---

## 🎛️ Advanced Options & Tuning

- concurrency: Number of simultaneous connection attempts. Increase for faster scans on local networks; decrease for unreliable/remote networks.
- timeout: Per-connection timeout (seconds). Increase for high-latency networks.
- retries: Number of connection retries (useful when intermediate devices drop packets).
- rate_limit: If set, attempts to roughly limit operations per second to avoid bursts.
- udp: When true, the scanner will attempt a simple UDP probe in addition to TCP open detection for ports marked open.

Performance tips:
- On a machine with many open sockets and good network, concurrency=1000+ can be used for massive throughput, but test carefully.
- For public Internet scanning, be conservative: concurrency=50–200 and rate_limit to polite values.

---

## 📤 Exports & Persistence

- JSON: .export_json(path) writes a list of result objects.
- CSV: .export_csv(path) writes result rows with all keys discovered.
- SQLite: Pass sqlite_db="scans.db" to the constructor and the scanner will insert rows into a scans table:

Schema (approx):

```
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT,
  port INTEGER,
  status TEXT,
  service TEXT,
  banner TEXT,
  timestamp REAL
)
```

This makes it easy to query historical scans.

---

## 🚨 Safety & Legal

- Only scan systems you own or are explicitly authorized to test.
- Respect robots / corporate policies and rate-limit aggressively on networks you do not control.
- SYN scans use raw sockets and may be blocked or logged by defensive systems.

---

## 🐞 Troubleshooting & FAQ

Q: I get permissions errors when using SYN scans.
A: Run as root/administrator or avoid SYN scans (use TCP connect scans). Scapy requires OS-level capabilities for raw sockets.

Q: Why are UDP results unreliable?
A: UDP is connectionless; many services don't respond to empty probes. ICMP responses (port unreachable) are the reliable indicator but may be filtered.

Q: How do I detect service versions more accurately?
A: Extend the banner parsing in discn/scs.py or post-process banners in your scripts. The scanner performs simple heuristics by default.

Q: I need a CLI executable.
A: You can write a small entry point that parses argparse and creates NetworkScanner with chosen options. If you want, I can add a ready-to-use CLI wrapper.

---

## ��� Development & Tests

- If you contribute, add unit tests for target/port parsing and mock network behavior for scanning logic.
- Consider adding GitHub Actions to run tests on push/pull requests.

---

## 📜 Changelog (selected)

- v0.1 — Initial implementation: async TCP scanning, basic banner grabbing, exports.
- v0.2 — Added SYN scan (scapy), UDP probe, improved parsing and rich UI.

---

## 🧾 License

Please add a LICENSE file if you intend to publish this as open source. By default, include an OSI-approved license of your choice (MIT, Apache-2.0, etc.).

---

## 👤 Author

SCS is created and maintained by suvscd (solo). Thanks for building and improving.
