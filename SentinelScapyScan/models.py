"""
Data models for scan results.

This module defines the core data structures used throughout the scanning process.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class PortResult:
    """
    Represents the result of scanning a single port.
    
    Attributes:
        port: Port number
        status: Port status ("open", "closed", "filtered")
        service: Identified service name (optional)
        banner: Service banner text (optional)
        http_headers: HTTP headers if applicable (optional)
        tls_info: TLS/SSL information if applicable (optional)
    """
    port: int
    status: str
    service: Optional[str] = None
    banner: Optional[str] = None
    http_headers: Optional[Dict[str, Any]] = None
    tls_info: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert PortResult to dictionary for serialization."""
        return {
            "port": self.port,
            "status": self.status,
            "service": self.service,
            "banner": self.banner,
            "http_headers": self.http_headers,
            "tls_info": self.tls_info,
        }


@dataclass
class HostResult:
    """
    Represents the complete scan result for a single host.
    
    Attributes:
        ip: Target IP address
        reachable: Whether the host is reachable
        ports: List of port scan results
        scan_time: Timestamp of the scan
        scan_duration: Duration of the scan in seconds
    """
    ip: str
    reachable: bool
    ports: List[PortResult] = field(default_factory=list)
    scan_time: Optional[datetime] = None
    scan_duration: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert HostResult to dictionary for serialization."""
        return {
            "ip": self.ip,
            "reachable": self.reachable,
            "ports": [port.to_dict() for port in self.ports],
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "scan_duration": self.scan_duration,
            "total_ports_scanned": len(self.ports),
            "open_ports": len([p for p in self.ports if p.status == "open"]),
            "closed_ports": len([p for p in self.ports if p.status == "closed"]),
            "filtered_ports": len([p for p in self.ports if p.status == "filtered"]),
        }
    
    def get_open_ports(self) -> List[PortResult]:
        """Return only open ports."""
        return [port for port in self.ports if port.status == "open"]
    
    def get_services(self) -> List[str]:
        """Return list of identified services."""
        return [port.service for port in self.ports if port.service]
