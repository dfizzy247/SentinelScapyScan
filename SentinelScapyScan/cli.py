"""
Command-line interface for SentinelScapyScan.

Provides CLI commands for scanning, reporting, and fingerprinting.
"""

import typer
from typing import Optional, List
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import print as rprint
import time

from SentinelScapyScan.manager import ScanManager
from SentinelScapyScan.utils.logging import setup_logging, get_logger, log_scan_summary
from SentinelScapyScan.utils.config import load_config, get_default_config, get_port_list
from SentinelScapyScan.reporting.json_writer import write_json_report, export_to_csv
from SentinelScapyScan.reporting.html_report import generate_html_report

app = typer.Typer(
    name="sentinelscapyscan",
    help="SentinelScapyScan - Advanced Network Security Scanner",
    add_completion=False
)

console = Console()
logger = None


@app.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress output"),
):
    """SentinelScapyScan - Network Security Scanner"""
    global logger
    
    # Determine log level
    if debug:
        log_level = "DEBUG"
    elif verbose:
        log_level = "INFO"
    elif quiet:
        log_level = "ERROR"
    else:
        log_level = "INFO"
    
    # Setup logging
    setup_logging(level=log_level)
    logger = get_logger(__name__)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP address, hostname, or CIDR range"),
    ports: str = typer.Option(
        "default",
        "--ports", "-p",
        help="Ports to scan (e.g., '80,443,8080-8090' or 'common' or 'all')"
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (without extension)"
    ),
    timeout: int = typer.Option(3, "--timeout", "-t", help="Timeout in seconds"),
    udp: bool = typer.Option(False, "--udp", help="Enable UDP scanning"),
    no_fingerprint: bool = typer.Option(
        False,
        "--no-fingerprint",
        help="Disable service fingerprinting"
    ),
    skip_ping: bool = typer.Option(
        False,
        "--skip-ping",
        help="Skip host reachability check"
    ),
    json_output: bool = typer.Option(True, "--json/--no-json", help="Generate JSON report"),
    html_output: bool = typer.Option(True, "--html/--no-html", help="Generate HTML report"),
    csv_output: bool = typer.Option(False, "--csv", help="Generate CSV report"),
    config_file: Optional[str] = typer.Option(
        None,
        "--config", "-c",
        help="Path to configuration file"
    ),
):
    """
    Perform network scan on target(s).
    
    Examples:
    
        sentinelscapyscan scan 192.168.1.1
        
        sentinelscapyscan scan 192.168.1.1 -p 80,443,8080-8090
        
        sentinelscapyscan scan 192.168.1.0/24 -p common --udp
        
        sentinelscapyscan scan example.com -o my_scan --no-fingerprint
    """
    logger.info(f"Starting scan of target: {target}")
    
    # Load configuration
    if config_file:
        config = load_config(config_file)
    else:
        config = get_default_config()
    
    # Parse ports
    port_list = get_port_list(config, ports)
    
    if not port_list:
        console.print("[red]Error: No valid ports specified[/red]")
        raise typer.Exit(1)
    
    console.print(f"\n[bold blue]=== SentinelScapyScan ===[/bold blue]")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Ports:[/bold] {len(port_list)} ports")
    console.print(f"[bold]Timeout:[/bold] {timeout}s")
    console.print(f"[bold]UDP Scan:[/bold] {'Enabled' if udp else 'Disabled'}")
    console.print(f"[bold]Fingerprinting:[/bold] {'Enabled' if not no_fingerprint else 'Disabled'}\n")
    
    # Initialize scan manager
    scan_manager = ScanManager(
        timeout=timeout,
        enable_udp=udp,
        enable_fingerprinting=not no_fingerprint
    )
    
    # Perform scan with progress bar
    start_time = time.time()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        # Scanning task
        scan_task = progress.add_task(
            f"[cyan]Scanning {target}...",
            total=len(port_list)
        )
        
        try:
            result = scan_manager.scan_host(target, port_list, skip_ping=skip_ping)
            progress.update(scan_task, completed=len(port_list))
        except PermissionError:
            console.print("\n[red]Error: This scan requires root/administrator privileges[/red]")
            console.print("[yellow]Please run with sudo (Linux/Mac) or as Administrator (Windows)[/yellow]")
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"\n[red]Error during scan: {e}[/red]")
            logger.error(f"Scan failed: {e}", exc_info=True)
            raise typer.Exit(1)
    
    scan_duration = time.time() - start_time
    
    # Display results
    _display_scan_results(result)
    
    # Generate reports
    if output:
        output_base = Path(output)
        output_base.parent.mkdir(parents=True, exist_ok=True)
        
        results_list = [result]
        
        if json_output:
            json_path = f"{output_base}.json"
            write_json_report(results_list, json_path, config)
            console.print(f"\n[green][+] JSON report saved to: {json_path}[/green]")
        
        if html_output:
            html_path = f"{output_base}.html"
            generate_html_report(results_list, html_path, config)
            console.print(f"[green][+] HTML report saved to: {html_path}[/green]")
        
        if csv_output:
            csv_path = f"{output_base}.csv"
            export_to_csv(results_list, csv_path)
            console.print(f"[green][+] CSV report saved to: {csv_path}[/green]")
    
    # Summary
    log_scan_summary(
        total_hosts=1,
        reachable_hosts=1 if result.reachable else 0,
        total_open_ports=len(result.get_open_ports()),
        scan_duration=scan_duration
    )


@app.command()
def report(
    input_file: str = typer.Argument(..., help="Input JSON report file"),
    output: str = typer.Option(
        "report.html",
        "--output", "-o",
        help="Output HTML file path"
    ),
):
    """
    Generate HTML report from JSON scan results.
    
    Example:
        sentinelscapyscan report scan_results.json -o report.html
    """
    logger.info(f"Generating report from {input_file}")
    
    try:
        from SentinelScapyScan.reporting.json_writer import load_json_report
        
        # Load JSON report
        report_data = load_json_report(input_file)
        
        # Convert to HostResult objects
        from SentinelScapyScan.models import HostResult, PortResult
        from datetime import datetime
        
        results = []
        for host_data in report_data.get("results", []):
            ports = [
                PortResult(
                    port=p["port"],
                    status=p["status"],
                    service=p.get("service"),
                    banner=p.get("banner"),
                    http_headers=p.get("http_headers"),
                    tls_info=p.get("tls_info")
                )
                for p in host_data.get("ports", [])
            ]
            
            host = HostResult(
                ip=host_data["ip"],
                reachable=host_data["reachable"],
                ports=ports,
                scan_time=datetime.fromisoformat(host_data["scan_time"]) if host_data.get("scan_time") else None,
                scan_duration=host_data.get("scan_duration")
            )
            results.append(host)
        
        # Generate HTML report
        generate_html_report(results, output, report_data.get("scan_configuration"))
        
        console.print(f"\n[green][+] HTML report generated: {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise typer.Exit(1)


@app.command()
def fingerprint(
    target: str = typer.Argument(..., help="Target IP address or hostname"),
    port: int = typer.Argument(..., help="Port number"),
    http: bool = typer.Option(False, "--http", help="HTTP fingerprinting"),
    https: bool = typer.Option(False, "--https", help="HTTPS fingerprinting"),
    tls: bool = typer.Option(False, "--tls", help="TLS fingerprinting"),
    banner: bool = typer.Option(False, "--banner", help="Banner grabbing"),
    all_fp: bool = typer.Option(False, "--all", "-a", help="All fingerprinting methods"),
):
    """
    Perform service fingerprinting on a specific port.
    
    Examples:
        sentinelscapyscan fingerprint 192.168.1.1 80 --http
        
        sentinelscapyscan fingerprint example.com 443 --https --tls
        
        sentinelscapyscan fingerprint 192.168.1.1 22 --banner
    """
    logger.info(f"Fingerprinting {target}:{port}")
    
    if all_fp:
        http = https = tls = banner = True
    
    if not any([http, https, tls, banner]):
        console.print("[yellow]No fingerprinting method specified. Using --all[/yellow]")
        http = https = tls = banner = True
    
    console.print(f"\n[bold blue]>>> Fingerprinting {target}:{port}[/bold blue]\n")
    
    # Banner grabbing
    if banner:
        from SentinelScapyScan.fingerprinting.banner import grab_banner_with_probe
        
        with console.status("[cyan]Grabbing banner..."):
            banner_text = grab_banner_with_probe(target, port)
        
        if banner_text:
            console.print(f"[green][+] Banner:[/green]\n{banner_text}\n")
        else:
            console.print("[yellow][-] No banner received[/yellow]\n")
    
    # HTTP fingerprinting
    if http:
        from SentinelScapyScan.fingerprinting.http_fp import fingerprint_http_sync
        
        with console.status("[cyan]Fingerprinting HTTP..."):
            http_info = fingerprint_http_sync(target, port, use_https=False)
        
        if http_info:
            console.print("[green][+] HTTP Information:[/green]")
            console.print(f"  Server: {http_info.get('server', 'Unknown')}")
            console.print(f"  Status: {http_info.get('status_code', 'Unknown')}")
            if http_info.get('powered_by'):
                console.print(f"  Powered By: {http_info['powered_by']}")
            console.print()
        else:
            console.print("[yellow][-] HTTP fingerprinting failed[/yellow]\n")
    
    # HTTPS fingerprinting
    if https:
        from SentinelScapyScan.fingerprinting.http_fp import fingerprint_http_sync
        
        with console.status("[cyan]Fingerprinting HTTPS..."):
            https_info = fingerprint_http_sync(target, port, use_https=True)
        
        if https_info:
            console.print("[green][+] HTTPS Information:[/green]")
            console.print(f"  Server: {https_info.get('server', 'Unknown')}")
            console.print(f"  Status: {https_info.get('status_code', 'Unknown')}")
            console.print()
        else:
            console.print("[yellow][-] HTTPS fingerprinting failed[/yellow]\n")
    
    # TLS fingerprinting
    if tls:
        from SentinelScapyScan.fingerprinting.tls_fp import fingerprint_tls
        
        with console.status("[cyan]Fingerprinting TLS..."):
            tls_info = fingerprint_tls(target, port)
        
        if tls_info:
            console.print("[green][+] TLS Information:[/green]")
            console.print(f"  Version: {tls_info.get('tls_version', 'Unknown')}")
            cipher = tls_info.get('cipher_suite', {})
            console.print(f"  Cipher: {cipher.get('name', 'Unknown')}")
            
            cert = tls_info.get('certificate', {})
            if cert:
                subject = cert.get('subject', {})
                console.print(f"  Subject: {subject.get('CN', 'Unknown')}")
                issuer = cert.get('issuer', {})
                console.print(f"  Issuer: {issuer.get('CN', 'Unknown')}")
            console.print()
        else:
            console.print("[yellow][-] TLS fingerprinting failed[/yellow]\n")


def _display_scan_results(result):
    """Display scan results in a formatted table."""
    console.print(f"\n[bold]Scan Results for {result.ip}[/bold]")
    console.print(f"Reachable: {'[+] Yes' if result.reachable else '[-] No'}\n")
    
    if not result.ports:
        console.print("[yellow]No ports scanned[/yellow]")
        return
    
    # Create table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", width=8)
    table.add_column("Status", width=12)
    table.add_column("Service", width=15)
    table.add_column("Banner", width=50)
    
    for port in sorted(result.ports, key=lambda p: p.port):
        # Color status
        if port.status == "open":
            status = "[green]OPEN[/green]"
        elif port.status == "closed":
            status = "[red]CLOSED[/red]"
        else:
            status = "[yellow]FILTERED[/yellow]"
        
        # Truncate banner
        banner = port.banner[:47] + "..." if port.banner and len(port.banner) > 50 else (port.banner or "-")
        
        table.add_row(
            str(port.port),
            status,
            port.service or "-",
            banner
        )
    
    console.print(table)
    console.print()


@app.command()
def version():
    """Show version information."""
    from SentinelScapyScan import __version__
    console.print(f"[bold blue]SentinelScapyScan[/bold blue] version [green]{__version__}[/green]")


if __name__ == "__main__":
    app()
