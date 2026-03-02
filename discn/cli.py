import click
import os
from discn.scs import NetworkScanner
from rich.console import Console
from rich.text import Text
from rich.panel import Panel

console = Console()

def show_banner():
    """Display a high-quality modern NETSUVAX ASCII banner in glowing cyan."""
    banner_raw = r"""
    _   _ ______ _____ _____ _    _  _    _   __   _   _ 
   | \ | |  ____|_   _/ ____| |  | || |  | |  \ \ / /  | |
   |  \| | |__    | || (___ | |  | || |  | |   \ V /   | |
   | . ` |  __|   | | \___ \| |  | || |  | |    > <    | |
   | |\  | |____ _| |_____) | |__| |\ \_/ /    / . \   |_|
   |_| \_|______|_____|_____/ \____/  \___/    /_/ \_\  (_)
    """
    
    # Create a nice gradient-styled border panel for the banner
    banner_text = Text(banner_raw, style="bold bright_cyan", justify="center")
    subtitle = Text("====  Advanced Network Scanner  ====", style="bold bright_magenta", justify="center")
    
    panel = Panel(
        Text.assemble(banner_text, "\n", subtitle),
        border_style="bright_blue",
        title="[bold bright_white]By SuvScd[/bold bright_white]",
        title_align="right",
        subtitle="[bold bright_green]STATUS: ONLINE[/bold bright_green]",
        subtitle_align="left"
    )
    console.print(panel)

@click.group()
def cli():
    """NETSUVAX - A fast, modern, and versatile network scanner."""
    pass

@cli.command()
def help():
    """Show usage instructions and examples."""
    show_banner()
    help_text = """
[bold cyan]Usage:[/bold cyan]
  python -m discn scan --targets <IP|CIDR|range|hostname> \[OPTIONS]

[bold cyan]Options:[/bold cyan]
  [bright_green]--ports[/bright_green]           Port range (e.g. "1-1024") or specific ports (e.g. "22,80,443")
  [bright_green]--scan-type[/bright_green]       Scan type: tcp (default), syn, udp, or ping
  [bright_green]--output-json[/bright_green]     Export results to JSON file
  [bright_green]--output-csv[/bright_green]      Export results to CSV file
  [bright_green]--timeout[/bright_green]         Connection timeout per port in seconds (default: 0.5)
  [bright_green]--threads[/bright_green]         Number of concurrent threads (default: 200)
  [bright_green]--banner/--no-banner[/bright_green] Enable/disable service banner grabbing (default: enabled)
  [bright_green]--verbose[/bright_green]         Enable detailed error outputs

[bold cyan]Examples:[/bold cyan]
  python -m discn scan --targets "example.com" --ports "80,443"
  python -m discn scan --targets "192.168.1.0/24" --scan-type syn
  python -m discn scan --targets "10.0.0.1-10.0.0.10" --output-csv output.csv --banner
  python -m discn scan --targets "192.168.1.1" --scan-type udp --ports "53,161"
  python -m discn scan --targets "192.168.1.0/24" --scan-type ping

[bold yellow]Tip:[/bold yellow]
  - Use [bold]--scan-type syn[/bold] for stealth scanning (Linux only, needs sudo/root).
  - Use [bold]--scan-type ping[/bold] for fast host discovery.
  - You can always use --help with any command for details.
"""
    console.print(help_text)

@cli.command()
@click.option('--targets', required=True, help='IP addresses or network ranges (e.g., "192.168.1.1/24, 10.0.0.5")')
@click.option('--ports', default='1-1024', help='Port range (e.g., "1-1024") or specific ports (e.g., "22,80,443")')
@click.option('--scan-type', default='tcp', type=click.Choice(['tcp', 'syn', 'udp', 'ping']), help='Scan type (TCP Connect, SYN Stealth, UDP, or Ping Sweep).')
@click.option('--output-json', help='Output results to a JSON file.')
@click.option('--output-csv', help='Output results to a CSV file.')
@click.option('--timeout', default=0.5, type=float, help='Connection timeout per target/port in seconds.')
@click.option('--threads', default=200, type=int, help='Number of concurrent threads.')
@click.option('--banner/--no-banner', default=True, help='Enable/disable service banner grabbing.')
@click.option('--verbose', is_flag=True, help='Enable verbose error reporting.')
def scan(targets, ports, scan_type, output_json, output_csv, timeout, threads, banner, verbose):
    """
    Perform a network scan directly from the command line.
    """
    show_banner()

    if scan_type in ['syn', 'udp'] and hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print("[bold red][!] SYN and UDP scans require root privileges. Please run with sudo.[/bold red]")
        return

    try:
        scanner = NetworkScanner(
            targets=targets,
            ports=ports,
            scan_type=scan_type,
            timeout=timeout,
            threads=threads,
            banner_grabbing=banner
        )
        scanner.run_scan_cli()

        if output_json:
            scanner.export_json(output_json)
        if output_csv:
            scanner.export_csv(output_csv)

    except Exception as e:
        if verbose:
            console.print_exception()
        else:
            console.print(f"[bold red][!] An error occurred: {e}[/bold red]")
