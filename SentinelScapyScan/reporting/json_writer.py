"""
JSON report writer.

Generates JSON reports from scan results.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from SentinelScapyScan.models import HostResult

logger = logging.getLogger(__name__)


def write_json_report(
    results: List[HostResult],
    output_path: str,
    config: Dict[str, Any] = None,
    pretty: bool = True
) -> None:
    """
    Write scan results to JSON file.
    
    Args:
        results: List of HostResult objects
        output_path: Path to output JSON file
        config: Optional scan configuration to include
        pretty: Pretty-print JSON (default: True)
        
    Example:
        >>> results = [host_result1, host_result2]
        >>> write_json_report(results, "scan_results.json")
    """
    logger.info(f"Writing JSON report to {output_path}")
    
    # Build report structure
    report = {
        "metadata": {
            "report_generated": datetime.now().isoformat(),
            "total_hosts": len(results),
            "total_open_ports": sum(
                len(host.get_open_ports()) for host in results
            ),
        },
        "scan_configuration": config or {},
        "results": [host.to_dict() for host in results]
    }
    
    # Add statistics
    report["statistics"] = _calculate_statistics(results)
    
    # Write to file
    try:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(report, f, indent=2, ensure_ascii=False)
            else:
                json.dump(report, f, ensure_ascii=False)
        
        logger.info(f"JSON report written successfully to {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to write JSON report: {e}")
        raise


def _calculate_statistics(results: List[HostResult]) -> Dict[str, Any]:
    """
    Calculate statistics from scan results.
    
    Args:
        results: List of HostResult objects
        
    Returns:
        Dictionary of statistics
    """
    stats = {
        "total_hosts_scanned": len(results),
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
        
        stats["services_detected"] = service_counts
    
    # Average scan duration
    durations = [h.scan_duration for h in results if h.scan_duration]
    if durations:
        stats["average_scan_duration"] = sum(durations) / len(durations)
        stats["total_scan_time"] = sum(durations)
    
    return stats


def load_json_report(input_path: str) -> Dict[str, Any]:
    """
    Load JSON report from file.
    
    Args:
        input_path: Path to JSON report file
        
    Returns:
        Dictionary containing report data
    """
    logger.info(f"Loading JSON report from {input_path}")
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        logger.info(f"JSON report loaded successfully from {input_path}")
        return report
        
    except Exception as e:
        logger.error(f"Failed to load JSON report: {e}")
        raise


def export_to_csv(results: List[HostResult], output_path: str) -> None:
    """
    Export scan results to CSV format.
    
    Args:
        results: List of HostResult objects
        output_path: Path to output CSV file
    """
    import csv
    
    logger.info(f"Exporting results to CSV: {output_path}")
    
    try:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'IP Address',
                'Reachable',
                'Port',
                'Status',
                'Service',
                'Banner'
            ])
            
            # Write data
            for host in results:
                if not host.ports:
                    writer.writerow([
                        host.ip,
                        host.reachable,
                        '',
                        '',
                        '',
                        ''
                    ])
                else:
                    for port in host.ports:
                        writer.writerow([
                            host.ip,
                            host.reachable,
                            port.port,
                            port.status,
                            port.service or '',
                            port.banner or ''
                        ])
        
        logger.info(f"CSV export completed: {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to export CSV: {e}")
        raise
