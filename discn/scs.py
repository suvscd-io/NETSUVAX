import socket
import ipaddress
import threading
import json
import csv
import time
import os
from queue import Queue, Empty
from scapy.all import IP, TCP, sr1, conf
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

# Disable Scapy's verbose output
conf.verb = 0
console = Console()

class NetworkScanner:
    def __init__(self, targets, ports, scan_type='tcp', timeout=0.5, threads=200, banner_grabbing=True):
        try:
            self.targets = self._parse_targets(targets)
            self.ports = self._parse_ports(ports)
        except ValueError as e:
            console.print(f"[bold red]Configuration error: {e}[/bold red]")
            raise

        self.scan_type = scan_type
        self.timeout = max(0.1, min(float(timeout), 10.0))  # Clamp timeout between 0.1 and 10 seconds
        self.threads = max(1, min(int(threads), 1000))      # Clamp threads between 1 and 1000
        self.banner_grabbing = banner_grabbing
        self.results = []
        self.scan_queue = Queue()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()

    def _parse_targets(self, targets_str):
        """Parse target IP addresses and networks with proper validation"""
        if not targets_str or not targets_str.strip():
            raise ValueError("No targets specified")

        targets = set()
        for target in targets_str.split(','):
            target = target.strip()
            if not target:
                continue

            if '/' in target:
                # CIDR notation
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    target_count = 0
                    for ip in network.hosts():
                        targets.add(str(ip))
                        target_count += 1
                        if target_count >= 1000:  # Prevent scanning too many hosts
                            console.print(f"[yellow]Warning: Limiting network {target} to first 1000 hosts[/yellow]")
                            break
                except (ipaddress.AddressValueError, ValueError) as e:
                    console.print(f"[yellow]Warning: Invalid CIDR network '{target}': {e}[/yellow]")
            elif '-' in target:
                # IP range e.g. 192.168.1.1-192.168.1.10
                parts = target.split('-', 1)
                if len(parts) == 2:
                    start_ip, end_ip = parts
                    start_ip, end_ip = start_ip.strip(), end_ip.strip()
                    try:
                        start = ipaddress.ip_address(start_ip)
                        end = ipaddress.ip_address(end_ip)
                        if type(start) != type(end):
                            raise ValueError("Start and end IP address versions do not match")
                        current = start
                        count = 0
                        while current <= end and count < 1000:
                            targets.add(str(current))
                            current += 1
                            count += 1
                        if count >= 1000:
                            console.print(f"[yellow]Warning: Limiting IP range {target} to first 1000 addresses[/yellow]")
                    except (ipaddress.AddressValueError, ValueError):
                        # Not a valid IP range, treat as hostname
                        try:
                            resolved_ip = socket.gethostbyname(target)
                            targets.add(resolved_ip)
                            console.print(f"[cyan]Resolved {target} to {resolved_ip}[/cyan]")
                        except socket.gaierror:
                            console.print(f"[yellow]Warning: Could not resolve hostname '{target}'[/yellow]")
                else:
                    # Invalid range format, treat as hostname
                    try:
                        resolved_ip = socket.gethostbyname(target)
                        targets.add(resolved_ip)
                        console.print(f"[cyan]Resolved {target} to {resolved_ip}[/cyan]")
                    except socket.gaierror:
                        console.print(f"[yellow]Warning: Could not resolve hostname '{target}'[/yellow]")
            else:
                # Single IP address or hostname
                try:
                    ipaddress.ip_address(target)
                    targets.add(target)
                except (ipaddress.AddressValueError, ValueError):
                    try:
                        resolved_ip = socket.gethostbyname(target)
                        targets.add(resolved_ip)
                        console.print(f"[cyan]Resolved {target} to {resolved_ip}[/cyan]")
                    except socket.gaierror:
                        console.print(f"[yellow]Warning: Could not resolve hostname '{target}'[/yellow]")

        if not targets:
            raise ValueError("No valid targets found after parsing")

        valid_targets = []
        for target in targets:
            try:
                ipaddress.ip_address(target)
                valid_targets.append(target)
            except (ipaddress.AddressValueError, ValueError):
                console.print(f"[yellow]Warning: Skipping invalid target '{target}' in final validation[/yellow]")

        if not valid_targets:
            raise ValueError("No valid IP addresses found after hostname resolution")

        return sorted(valid_targets, key=ipaddress.ip_address)

    def _parse_ports(self, ports_str):
        """Parse port specification with proper validation"""
        if not ports_str or not ports_str.strip():
            raise ValueError("No ports specified")

        ports = set()
        try:
            for port_spec in ports_str.split(','):
                port_spec = port_spec.strip()
                if not port_spec:
                    continue

                if '-' in port_spec:
                    try:
                        start, end = port_spec.split('-', 1)
                        start_port = int(start.strip())
                        end_port = int(end.strip())
                        if start_port < 1 or end_port > 65535 or start_port > end_port:
                            raise ValueError(f"Invalid port range: {port_spec}")

                        # Limit to first 10000 ports
                        max_ports = 10000
                        for port in range(start_port, min(end_port + 1, start_port + max_ports)):
                            ports.add(port)

                        if (end_port - start_port + 1) > max_ports:
                            console.print(f"[yellow]Warning: Limiting port range {port_spec} to first {max_ports} ports ({start_port}-{start_port+max_ports-1})[/yellow]")
                    except ValueError as e:
                        raise ValueError(f"Invalid port range '{port_spec}': {e}")
                else:
                    port = int(port_spec)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port {port} out of valid range (1-65535)")
                    ports.add(port)

        except ValueError as e:
            raise ValueError(f"Error parsing ports: {e}")

        if not ports:
            raise ValueError("No valid ports found after parsing")
        return sorted(list(ports))

    def _grab_banner(self, sock):
        """Safely grab banner from socket with timeout"""
        try:
            sock.settimeout(self.timeout)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:500]  # Limit banner length
        except (socket.timeout, socket.error, UnicodeDecodeError):
            return ''

    def _tcp_scan(self, target, port):
        """Perform TCP connect scan with proper error handling"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))

                if result == 0:
                    banner = self._grab_banner(sock) if self.banner_grabbing else ''
                    return 'open', banner
                else:
                    return 'closed', ''
        except socket.timeout:
            return 'filtered', ''
        except socket.error as e:
            return 'error', f'Socket error: {str(e)[:100]}'
        except Exception as e:
            return 'error', f'Unexpected error: {str(e)[:100]}'

    def _syn_scan(self, target, port):
        """Perform SYN stealth scan with proper error handling"""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return 'error', 'SYN scan requires root privileges'
        try:
            syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response is None:
                return 'filtered', ''
            elif response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                if tcp_flags == 0x12:  # SYN-ACK
                    # Send RST to close connection cleanly
                    rst_packet = IP(dst=target) / TCP(dport=port, flags="R", seq=response.getlayer(TCP).ack)
                    sr1(rst_packet, timeout=self.timeout, verbose=0)
                    return 'open', ''
                elif tcp_flags == 0x14:  # RST-ACK
                    return 'closed', ''
                else:
                    return 'filtered', ''
            else:
                return 'filtered', ''
        except Exception as e:
            return 'error', f'SYN scan error: {str(e)[:100]}'

    def _identify_service(self, port, banner):
        """Identify service based on port and banner"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 119: "NNTP", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 3389: "RDP", 5432: "PostgreSQL",
            3306: "MySQL", 1433: "MSSQL", 6379: "Redis", 5900: "VNC"
        }

        service = common_services.get(port, "Unknown")

        # Refine based on banner
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service = "SSH"
            elif "http" in banner_lower:
                service = "HTTPS" if "ssl" in banner_lower or port == 443 else "HTTP"
            elif "ftp" in banner_lower:
                service = "FTP"
            elif "mysql" in banner_lower:
                service = "MySQL"
            elif "postgres" in banner_lower:
                service = "PostgreSQL"

        return service

    def _worker(self):
        """Worker thread for scanning with proper error handling"""
        while not self.stop_event.is_set():
            try:
                target, port = self.scan_queue.get(timeout=1.0)

                if self.scan_type == 'tcp':
                    status, banner = self._tcp_scan(target, port)
                elif self.scan_type == 'syn':
                    status, banner = self._syn_scan(target, port)
                else:
                    status, banner = 'error', 'Invalid scan type'

                service = self._identify_service(port, banner)

                if status == 'open':
                    result = {
                        'target': target,
                        'port': port,
                        'status': status,
                        'service': service,
                        'banner': banner,
                        'timestamp': time.time()
                    }
                    with self.lock:
                        self.results.append(result)

                self.scan_queue.task_done()

            except Empty:
                continue  # Check for stop event and continue
            except Exception as e:
                import traceback
                console.print(f"[red]Worker thread error: {e}[/red]")
                traceback.print_exc()
                try:
                    self.scan_queue.task_done()
                except Exception:
                    pass

    def run_scan_cli(self):
        """Run scan with CLI progress display"""
        try:
            console.print(f"[cyan]Starting scan of {len(self.targets)} target(s) and {len(self.ports)} port(s)[/cyan]")
            console.print(f"[cyan]Scan type: {self.scan_type.upper()}, Timeout: {self.timeout}s, Threads: {self.threads}[/cyan]")

            # Populate queue
            for target in self.targets:
                for port in self.ports:
                    self.scan_queue.put((target, port))

            total_tasks = self.scan_queue.qsize()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]Scanning {len(self.targets)} hosts...", total=total_tasks)

                # Start worker threads
                threads = []
                for _ in range(self.threads):
                    thread = threading.Thread(target=self._worker, daemon=True)
                    thread.start()
                    threads.append(thread)

                # Monitor progress
                while not progress.finished:
                    completed = total_tasks - self.scan_queue.qsize()
                    progress.update(task, completed=completed)
                    if completed >= total_tasks:
                        break
                    time.sleep(0.1)

                # Wait for completion
                self.scan_queue.join()
                self.stop_event.set()

                # Wait for all threads to finish
                for thread in threads:
                    thread.join(timeout=1)

            self._print_results_table()
            return self.results

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            self.stop_event.set()
            # Try to join threads (best-effort)
            return self.results
        except Exception as e:
            console.print(f"[red]Error during scan: {e}[/red]")
            self.stop_event.set()
            raise

    def _print_results_table(self):
        """Print scan results in a formatted table"""
        if not self.results:
            console.print("\n[yellow]No open ports found.[/yellow]")
            return

        table = Table(title="Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("Target IP", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("Status", style="green")
        table.add_column("Service", style="blue")
        table.add_column("Banner", style="yellow")

        for result in sorted(self.results, key=lambda x: (ipaddress.ip_address(x['target']), x['port'])):
            banner_preview = (result['banner'][:60] + '...') if len(result['banner']) > 60 else result['banner']
            table.add_row(
                result['target'],
                str(result['port']),
                result['status'],
                result['service'],
                banner_preview
            )

        console.print(table)
        console.print(f"\n[green]Found {len(self.results)} open ports[/green]")

    def export_json(self, filename):
        """Export results to JSON file"""
        if not self.results:
            console.print("[yellow]No results to export[/yellow]")
            return

        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            console.print(f"\n[green]Results exported to {filename}[/green]")
        except IOError as e:
            console.print(f"\n[bold red]Error exporting to JSON: {e}[/bold red]")

    def export_csv(self, filename):
        """Export results to CSV file"""
        if not self.results:
            console.print("[yellow]No results to export[/yellow]")
            return

        # Gather all keys across all results for CSV header
        all_keys = set()
        for r in self.results:
            all_keys.update(r.keys())
        fieldnames = sorted(all_keys)

        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.results)
            console.print(f"\n[green]Results exported to {filename}[/green]")
        except IOError as e:
            console.print(f"\n[bold red]Error exporting to CSV: {e}[/bold red]")
