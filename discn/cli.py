import click
import os
from .scs import NetworkScanner

def show_banner():
    """Display modern SCS ASCII banner with bee"""
    banner = """
 ███████  ███████  ███████           •><•
 ██       ██       ██                ^^v^^
 ███████  ██       ███████          •><•><•
       ██ ██             ██         ^^vvv^^
 ███████  ███████  ███████          •><•><•
                                      ^^^
         ═══ By SuvScd ═══
    ••••••••••••••••••••••••••••••••
"""
    click.echo(click.style(banner, fg="cyan", bold=True))

@click.group()
def cli():
    """SCS - A fast and versatile network scanner."""
    pass

@cli.command()
@click.option('--targets', required=True, help='IP addresses or network ranges (e.g., "192.168.1.1/24, 10.0.0.5")')
@click.option('--ports', default='1-1024', help='Port range (e.g., "1-1024") or specific ports (e.g., "22,80,443")')
@click.option('--scan-type', default='tcp', type=click.Choice(['tcp', 'syn']), help='Scan type (TCP Connect or SYN Stealth).')
@click.option('--output-json', help='Output results to a JSON file.')
@click.option('--output-csv', help='Output results to a CSV file.')
@click.option('--timeout', default=0.5, help='Connection timeout per port in seconds.')
@click.option('--threads', default=200, help='Number of concurrent threads.')
@click.option('--banner/--no-banner', default=True, help='Enable/disable service banner grabbing.')
def scan(targets, ports, scan_type, output_json, output_csv, timeout, threads, banner):
    """
    Perform a network scan directly from the command line.
    """
    show_banner()  # 🎨 BANNER SCS AJOUTÉ ICI !
    
    if scan_type == 'syn' and os.geteuid() != 0:
        click.echo(click.style("[-] SYN scan requires root privileges. Please run with sudo.", fg="red"))
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
        click.echo(click.style(f"[!] An error occurred: {e}", fg="red"))

if __name__ == "__main__":
    cli()
