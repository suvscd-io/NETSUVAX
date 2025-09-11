# SCS

SCS is a lightweight network scanning toolkit. This update documents the new NetworkScanner implementation (discn/scs.py) and how to use it from the command line or as a Python library.

## New: NetworkScanner (discn/scs.py)

The NetworkScanner is a feature-rich, async-capable network scanner that provides:

- High-concurrency async TCP connect scanning (asyncio)
- Optional SYN stealth scans (scapy) — requires root/administrator privileges
- Basic UDP probe best-effort detection
- Banner grabbing with retries and configurable timeouts
- Rate limiting (concurrency and per-second)
- Export results to JSON, CSV, or SQLite
- Rich console UI using rich (progress and table output)
- Robust target (CIDR, ranges, hostnames) and port parsing with sensible limits and warnings

File: discn/scs.py

## Installation

Install the dependencies used by the scanner:

```bash
pip install scapy rich
```

Note: scapy may require additional system-level dependencies on some platforms. On Linux, run the scanner with root privileges for SYN scans.

## Quick usage examples

As a library (Python):

```python
from discn.scs import NetworkScanner

# scan a single host for a few ports
scanner = NetworkScanner(targets="192.0.2.10", ports="22,80,443", scan_type="tcp", timeout=1.0, concurrency=200, banner_grabbing=True, retries=1)
results = scanner.run_scan_cli()

# print/export
scanner.export_json("scan_results.json")
scanner.export_csv("scan_results.csv")
```

Run a SYN stealth scan (requires root and scapy):

```python
scanner = NetworkScanner(targets="198.51.100.0/30", ports="1-1024", scan_type="syn", concurrency=100)
results = scanner.run_scan_cli()
```

From an async context (programmatic high-concurrency scanning):

```python
import asyncio
from discn.scs import NetworkScanner

async def main():
    scanner = NetworkScanner(targets="203.0.113.5", ports="80,443", scan_type="tcp", concurrency=500, timeout=0.5)
    results = await scanner.run_scan_async()
    scanner.export_json("async_results.json")

asyncio.run(main())
```

## Command-line / integration notes

- The module provides run_scan_cli() which will dispatch to the async runner for TCP scans and use a synchronous scapy-based runner for SYN scans.
- Banner grabbing attempts a small initial read and, for HTTP-like services, will send a simple GET probe to elicit a response.
- UDP probing is best-effort and cannot reliably distinguish all states without raw/privileged sockets.

## Exporting results

- Use export_json(path), export_csv(path) or supply an sqlite_db filename to the constructor to persist scan results into a sqlite database.

## Safety, rate limits and etiquette

- Respect the target network's rules and only scan systems you are authorized to test.
- The scanner provides concurrency and rate_limit controls — tune them to avoid overloading networks or devices.
- SYN scans use raw sockets and require elevated privileges; if you do not have permission to use raw sockets, use TCP connect scans instead.

## Troubleshooting

- If scapy cannot be imported or fails to send/receive raw packets, ensure it's installed correctly and you have required OS capabilities.
- If many hosts/ports are being scanned, increase timeouts or decrease concurrency when running across unstable networks.

## Contributing

Contributions welcome: please open issues or PRs on the repository. If you want tests or a CLI wrapper script added, open an issue describing the desired behavior.
