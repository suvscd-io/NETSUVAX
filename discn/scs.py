import socket
import ipaddress
import threading
import json
import csv
import time
import os
import platform
import subprocess
import concurrent.futures
from typing import List, Set, Tuple, Dict, Any, Optional

from scapy.all import IP, TCP, UDP, ICMP, sr1, conf
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

# Disable Scapy's verbose output
conf.verb = 0
console = Console()

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 119: "NNTP", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 3389: "RDP", 5432: "PostgreSQL",
    3306: "MySQL", 1433: "MSSQL", 6379: "Redis", 5900: "VNC"
}

def is_root() -> bool:
    """Check if the current process has root privileges."""
    return not (hasattr(os, "geteuid") and os.geteuid() != 0)


class NetworkScanner:
    def __init__(
        self,
        targets: str,
        ports: str,
        scan_type: str = 'tcp',
        timeout: float = 0.5,
        threads: int = 200,
        banner_grabbing: bool = True
    ):
        self.scan_type = scan_type.lower()
        self.timeout = max(0.1, min(float(timeout), 10.0))
        self.threads = max(1, min(int(threads), 5000))
        self.banner_grabbing = banner_grabbing
        self.results: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

        # Validate privilege for raw socket scans
        if self.scan_type in ('syn', 'udp') and not is_root():
            raise PermissionError(f"{self.scan_type.upper()} scan requires root privileges.")

        try:
            self.targets = self._parse_targets(targets)
            self.ports = self._parse_ports(ports) if self.scan_type != 'ping' else []
        except ValueError as e:
            console.print(f"[bold red]Configuration error: {e}[/bold red]")
            raise

    def _parse_targets(self, targets_str: str) -> List[str]:
        if not targets_str or not targets_str.strip():
            raise ValueError("No targets specified")

        targets: Set[str] = set()
        for target in (t.strip() for t in targets_str.split(',') if t.strip()):
            if '/' in target:
                self._add_cidr(target, targets)
            elif '-' in target:
                self._add_range(target, targets)
            else:
                self._add_single_or_resolve(target, targets)

        if not targets:
            raise ValueError("No valid targets found after parsing")

        valid_targets = []
        for target in targets:
            try:
                ipaddress.ip_address(target)
                valid_targets.append(target)
            except ValueError:
                pass

        if not valid_targets:
            raise ValueError("No valid IP addresses found after hostname resolution")

        return sorted(valid_targets, key=ipaddress.ip_address)

    def _add_cidr(self, target: str, targets: Set[str]) -> None:
        try:
            network = ipaddress.ip_network(target, strict=False)
            targets.update(str(ip) for ip in network.hosts())
        except ValueError as e:
            console.print(f"[yellow]Warning: Invalid CIDR network '{target}': {e}[/yellow]")

    def _add_range(self, target: str, targets: Set[str]) -> None:
        parts = target.split('-', 1)
        if len(parts) == 2:
            start_ip, end_ip = parts[0].strip(), parts[1].strip()
            try:
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
                if type(start) != type(end):
                    raise ValueError("Start and end IP address versions do not match")

                current = int(start)
                end_int = int(end)
                while current <= end_int:
                    targets.add(str(ipaddress.ip_address(current)))
                    current += 1
            except ValueError:
                self._resolve_and_add(target, targets)
        else:
            self._resolve_and_add(target, targets)

    def _add_single_or_resolve(self, target: str, targets: Set[str]) -> None:
        try:
            ipaddress.ip_address(target)
            targets.add(target)
        except ValueError:
            self._resolve_and_add(target, targets)

    def _resolve_and_add(self, hostname: str, targets_set: Set[str]) -> None:
        try:
            resolved_ip = socket.gethostbyname(hostname)
            targets_set.add(resolved_ip)
            console.print(f"[cyan]Resolved {hostname} to {resolved_ip}[/cyan]")
        except socket.gaierror:
            console.print(f"[yellow]Warning: Could not resolve hostname '{hostname}'[/yellow]")

    def _parse_ports(self, ports_str: str) -> List[int]:
        if not ports_str or not ports_str.strip():
            raise ValueError("No ports specified")

        ports: Set[int] = set()
        try:
            for port_spec in (p.strip() for p in ports_str.split(',') if p.strip()):
                if '-' in port_spec:
                    start, end = port_spec.split('-', 1)
                    start_port, end_port = int(start.strip()), int(end.strip())
                    
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        raise ValueError(f"Invalid port range: {port_spec}")
                        
                    ports.update(range(start_port, end_port + 1))
                else:
                    port = int(port_spec)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port {port} out of valid range (1-65535)")
                    ports.add(port)
        except ValueError as e:
            raise ValueError(f"Error parsing ports: {e}")

        if not ports:
            raise ValueError("No valid ports found after parsing")
            
        return sorted(ports)

    def _grab_banner(self, sock: socket.socket) -> str:
        try:
            sock.settimeout(self.timeout)
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()[:500]
        except (socket.timeout, socket.error, UnicodeDecodeError):
            return ''

    def _tcp_scan(self, target: str, port: int) -> Tuple[str, str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((target, port)) == 0:
                    banner = self._grab_banner(sock) if self.banner_grabbing else ''
                    return 'open', banner
                return 'closed', ''
        except socket.timeout:
            return 'filtered', ''
        except Exception as e:
            return 'error', str(e)

    def _syn_scan(self, target: str, port: int) -> Tuple[str, str]:
        try:
            syn_packet = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response is None:
                return 'filtered', ''
            if response.haslayer(TCP):
                tcp_flags = response.getlayer(TCP).flags
                if tcp_flags == 0x12:  # SYN-ACK
                    rst_packet = IP(dst=target) / TCP(dport=port, flags="R", seq=response.getlayer(TCP).ack)
                    sr1(rst_packet, timeout=self.timeout, verbose=0)
                    return 'open', ''
                if tcp_flags == 0x14:  # RST-ACK
                    return 'closed', ''
            return 'filtered', ''
        except Exception as e:
            return 'error', str(e)

    def _udp_scan(self, target: str, port: int) -> Tuple[str, str]:
        try:
            udp_packet = IP(dst=target) / UDP(dport=port)
            response = sr1(udp_packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                return 'open|filtered', ''
            if response.haslayer(UDP):
                return 'open', ''
            if response.haslayer(ICMP):
                icmp = response.getlayer(ICMP)
                if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 9, 10, 13):
                    return 'filtered', ''
                if int(icmp.type) == 3 and int(icmp.code) == 3:
                    return 'closed', ''
            return 'filtered', ''
        except Exception as e:
            return 'error', str(e)

    def _ping_scan(self, target: str) -> Tuple[str, str]:
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), target]
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo
                )
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout))), target]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            return ('alive', '') if result.returncode == 0 else ('dead', '')
        except Exception as e:
            return 'error', str(e)

    def _identify_service(self, port: int, banner: str) -> str:
        service = COMMON_SERVICES.get(port, "Unknown")
        
        if banner:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                return "SSH"
            if "http" in banner_lower:
                return "HTTPS" if "ssl" in banner_lower or port == 443 else "HTTP"
            if "ftp" in banner_lower:
                return "FTP"
            if "mysql" in banner_lower:
                return "MySQL"
            if "postgres" in banner_lower:
                return "PostgreSQL"

        return service

    def _scan_worker(self, target: str, port: Optional[int] = None) -> None:
        if self.scan_type == 'tcp':
            status, banner = self._tcp_scan(target, port)
        elif self.scan_type == 'syn':
            status, banner = self._syn_scan(target, port)
        elif self.scan_type == 'udp':
            status, banner = self._udp_scan(target, port)
        elif self.scan_type == 'ping':
            status, banner = self._ping_scan(target)
            port = 0
        else:
            status, banner = 'error', 'Invalid scan type'

        if status in ('open', 'open|filtered', 'alive'):
            service = self._identify_service(port, banner) if port else 'Ping'
            result = {
                'target': target,
                'port': port if port else 'N/A',
                'status': status,
                'service': service,
                'banner': banner,
                'timestamp': time.time()
            }
            with self.lock:
                self.results.append(result)

    def run_scan_cli(self) -> List[Dict[str, Any]]:
        try:
            self._print_scan_summary()

            total_tasks = len(self.targets) if self.scan_type == 'ping' else len(self.targets) * len(self.ports)

            def task_generator():
                if self.scan_type == 'ping':
                    yield from ((target, None) for target in self.targets)
                else:
                    for target in self.targets:
                        for port in self.ports:
                            yield target, port

            tasks_gen = task_generator()

            with Progress(
                SpinnerColumn(spinner_name="dots2"),
                TextColumn("[bold bright_cyan]{task.description}"),
                BarColumn(bar_width=50, style="bright_black", complete_style="bright_green"),
                TextColumn("[bold bright_white]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task_id = progress.add_task("Scanning the network lattice...", total=total_tasks)

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = set()
                    
                    # Initial batch of futures
                    for _ in range(min(total_tasks, self.threads * 2)):
                        try:
                            t = next(tasks_gen)
                            futures.add(executor.submit(self._scan_worker, t[0], t[1]))
                        except StopIteration:
                            break
                            
                    while futures:
                        done, not_done = concurrent.futures.wait(
                            futures, return_when=concurrent.futures.FIRST_COMPLETED
                        )
                        futures = not_done
                        for future in done:
                            try:
                                future.result()
                            except Exception:
                                pass
                            
                            progress.update(task_id, advance=1)
                            
                            try:
                                t = next(tasks_gen)
                                futures.add(executor.submit(self._scan_worker, t[0], t[1]))
                            except StopIteration:
                                pass

            self._print_results_table()
            return self.results

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            return self.results
        except Exception as e:
            console.print(f"[red]Error during scan: {e}[/red]")
            raise

    def _print_scan_summary(self) -> None:
        summary = (
            f"[bold bright_green]Total Targets:[/bold bright_green] [white]{len(self.targets)}[/white]\n"
            f"[bold bright_green]Ports Target:[/bold bright_green] [white]{len(self.ports) if self.ports else 'N/A'}[/white]\n"
            f"[bold bright_green]Scan Mode:[/bold bright_green] [bright_yellow]{self.scan_type.upper()}[/bright_yellow]\n"
            f"[bold bright_green]Threads:[/bold bright_green] [white]{self.threads}[/white]\n"
            f"[bold bright_green]Timeout:[/bold bright_green] [white]{self.timeout}s[/white]"
        )
        console.print(Panel(
            summary, 
            title="[bold bright_magenta]❖ NETSUVAX Scan Initialized ❖[/bold bright_magenta]", 
            border_style="bright_cyan", 
            box=box.HEAVY, 
            expand=False
        ))

    def _print_results_table(self) -> None:
        success_results = [r for r in self.results if r.get('status') in ('open', 'open|filtered', 'alive')]
        if not success_results:
            console.print("\n[yellow]No positive results found.[/yellow]")
            return

        table = Table(
            title="[bold bright_green]❖ NETSUVAX Security Report ❖[/bold bright_green]", 
            show_header=True, 
            header_style="bold bright_magenta", 
            border_style="bright_cyan",
            box=box.HEAVY_EDGE,
            title_justify="center"
        )
        for col, style, justify in [
            ("Target IP", "bright_cyan", "center"),
            ("Port", "bright_yellow", "center"),
            ("Status", "bold bright_green", "center"),
            ("Service", "bright_white", "left"),
            ("Banner/Data", "bright_black", "left")
        ]:
            table.add_column(col, style=style, justify=justify)

        # Sort IP string cleanly
        sorted_results = sorted(success_results, key=lambda x: (
            ipaddress.ip_address(x['target']), 
            x['port'] if isinstance(x['port'], int) else 0
        ))

        for result in sorted_results:
            banner_str = str(result.get('banner', ''))
            banner_preview = f"{banner_str[:60]}..." if len(banner_str) > 60 else banner_str
            table.add_row(
                str(result['target']),
                str(result['port']),
                str(result['status']),
                str(result['service']),
                banner_preview
            )

        console.print(table)
        console.print(f"\n[green]Found {len(success_results)} results.[/green]")

    def export_json(self, filename: str) -> None:
        export_results = [r for r in self.results if r.get('status') in ('open', 'open|filtered', 'alive')]
        if not export_results:
            console.print("[yellow]No results to export[/yellow]")
            return

        try:
            with open(filename, 'w') as f:
                json.dump(export_results, f, indent=2, default=str)
            console.print(f"\n[green]Results exported to {filename}[/green]")
        except IOError as e:
            console.print(f"\n[bold red]Error exporting to JSON: {e}[/bold red]")

    def export_csv(self, filename: str) -> None:
        export_results = [r for r in self.results if r.get('status') in ('open', 'open|filtered', 'alive')]
        if not export_results:
            console.print("[yellow]No results to export[/yellow]")
            return

        fieldnames = sorted(set(k for r in export_results for k in r.keys()))

        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(export_results)
            console.print(f"\n[green]Results exported to {filename}[/green]")
        except IOError as e:
            console.print(f"\n[bold red]Error exporting to CSV: {e}[/bold red]")
