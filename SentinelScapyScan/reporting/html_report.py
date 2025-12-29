"""
HTML report generator.

Generates styled HTML reports from scan results using Jinja2 templates.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

from SentinelScapyScan.models import HostResult

logger = logging.getLogger(__name__)


def generate_html_report(
    results: List[HostResult],
    output_path: str,
    config: Dict[str, Any] = None,
    template_dir: str = None
) -> None:
    """
    Generate HTML report from scan results.
    
    Args:
        results: List of HostResult objects
        output_path: Path to output HTML file
        config: Optional scan configuration to include
        template_dir: Custom template directory (optional)
        
    Example:
        >>> results = [host_result1, host_result2]
        >>> generate_html_report(results, "scan_report.html")
    """
    logger.info(f"Generating HTML report to {output_path}")
    
    # Determine template directory
    if template_dir is None:
        template_dir = Path(__file__).parent / "templates"
    else:
        template_dir = Path(template_dir)
    
    if not template_dir.exists():
        logger.error(f"Template directory not found: {template_dir}")
        raise FileNotFoundError(f"Template directory not found: {template_dir}")
    
    # Setup Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Add custom filters
    env.filters['format_datetime'] = _format_datetime
    env.filters['format_duration'] = _format_duration
    
    # Load template
    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        logger.error(f"Failed to load template: {e}")
        raise
    
    # Prepare context data
    context = {
        "report_title": "SentinelScapyScan Report",
        "generated_at": datetime.now(),
        "results": results,
        "config": config or {},
        "statistics": _calculate_statistics(results),
        "summary": _generate_summary(results),
    }
    
    # Render template
    try:
        html_content = template.render(**context)
    except Exception as e:
        logger.error(f"Failed to render template: {e}")
        raise
    
    # Write to file
    try:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated successfully: {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to write HTML report: {e}")
        raise


def _format_datetime(dt: datetime) -> str:
    """Format datetime for display."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds is None:
        return "N/A"
    
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}h"


def _calculate_statistics(results: List[HostResult]) -> Dict[str, Any]:
    """Calculate statistics from scan results."""
    stats = {
        "total_hosts": len(results),
        "reachable_hosts": len([h for h in results if h.reachable]),
        "unreachable_hosts": len([h for h in results if not h.reachable]),
        "total_ports_scanned": sum(len(h.ports) for h in results),
        "total_open_ports": sum(len(h.get_open_ports()) for h in results),
        "total_closed_ports": sum(
            len([p for p in h.ports if p.status == "closed"]) for h in results
        ),
        "total_filtered_ports": sum(
            len([p for p in h.ports if p.status == "filtered"]) for h in results
        ),
    }
    
    # Service statistics
    all_services = []
    for host in results:
        all_services.extend(host.get_services())
    
    if all_services:
        service_counts = {}
        for service in all_services:
            service_counts[service] = service_counts.get(service, 0) + 1
        
        # Sort by count
        stats["top_services"] = sorted(
            service_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
    else:
        stats["top_services"] = []
    
    # Average scan duration
    durations = [h.scan_duration for h in results if h.scan_duration]
    if durations:
        stats["average_scan_duration"] = sum(durations) / len(durations)
        stats["total_scan_time"] = sum(durations)
    else:
        stats["average_scan_duration"] = 0
        stats["total_scan_time"] = 0
    
    return stats


def _generate_summary(results: List[HostResult]) -> Dict[str, Any]:
    """Generate summary information."""
    summary = {
        "hosts_with_open_ports": [],
        "most_common_ports": [],
        "hosts_with_vulnerabilities": [],
    }
    
    # Hosts with open ports
    for host in results:
        open_ports = host.get_open_ports()
        if open_ports:
            summary["hosts_with_open_ports"].append({
                "ip": host.ip,
                "open_port_count": len(open_ports),
                "ports": [p.port for p in open_ports]
            })
    
    # Most common open ports
    port_counts = {}
    for host in results:
        for port in host.get_open_ports():
            port_counts[port.port] = port_counts.get(port.port, 0) + 1
    
    if port_counts:
        summary["most_common_ports"] = sorted(
            port_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
    
    return summary
