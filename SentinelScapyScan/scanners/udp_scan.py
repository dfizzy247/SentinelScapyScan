"""
UDP scanner for UDP port scanning and service probing.

Implements DNS, NTP, and generic UDP probes to identify UDP services.
"""

from typing import List, Optional
from scapy.all import IP, UDP, DNS, DNSQR, sr1, Raw
import logging
from SentinelScapyScan.models import PortResult

logger = logging.getLogger(__name__)


def udp_scan(
    target: str,
    ports: List[int],
    timeout: int = 2,
    verbose: bool = False
) -> List[PortResult]:
    """
    Perform UDP scan on specified ports.
    
    Args:
        target: Target IP address or hostname
        ports: List of ports to scan
        timeout: Timeout in seconds for responses
        verbose: Enable verbose output
        
    Returns:
        List of PortResult objects
        
    Example:
        >>> results = udp_scan("192.168.1.1", [53, 123, 161])
        >>> for result in results:
        ...     print(f"Port {result.port}: {result.status} ({result.service})")
    """
    logger.info(f"Starting UDP scan on {target} for {len(ports)} ports")
    
    results = []
    
    for port in ports:
        result = _probe_udp_port(target, port, timeout, verbose)
        results.append(result)
    
    logger.info(f"UDP scan completed. Scanned {len(ports)} ports")
    return results


def _probe_udp_port(
    target: str,
    port: int,
    timeout: int,
    verbose: bool
) -> PortResult:
    """
    Probe a single UDP port with service-specific payloads.
    
    Args:
        target: Target IP address
        port: Port number
        timeout: Timeout in seconds
        verbose: Enable verbose output
        
    Returns:
        PortResult object
    """
    # Try service-specific probes first
    if port == 53:
        return _probe_dns(target, port, timeout, verbose)
    elif port == 123:
        return _probe_ntp(target, port, timeout, verbose)
    elif port == 161:
        return _probe_snmp(target, port, timeout, verbose)
    else:
        return _probe_generic_udp(target, port, timeout, verbose)


def _probe_dns(target: str, port: int, timeout: int, verbose: bool) -> PortResult:
    """
    Probe DNS service on port 53.
    
    Args:
        target: Target IP address
        port: Port number (typically 53)
        timeout: Timeout in seconds
        verbose: Enable verbose output
        
    Returns:
        PortResult object
    """
    try:
        # Create DNS query for version.bind
        dns_query = IP(dst=target) / UDP(dport=port) / DNS(
            rd=1,
            qd=DNSQR(qname="version.bind", qtype="TXT", qclass="CH")
        )
        
        response = sr1(dns_query, timeout=timeout, verbose=verbose)
        
        if response and response.haslayer(DNS):
            logger.debug(f"DNS service detected on {target}:{port}")
            return PortResult(
                port=port,
                status="open",
                service="dns"
            )
        elif response and response.haslayer("ICMP"):
            logger.debug(f"Port {port} is closed (ICMP unreachable)")
            return PortResult(port=port, status="closed")
        else:
            logger.debug(f"Port {port} is open|filtered (no response)")
            return PortResult(port=port, status="open|filtered", service="dns")
            
    except Exception as e:
        logger.error(f"DNS probe failed for {target}:{port}: {e}")
        return PortResult(port=port, status="filtered")


def _probe_ntp(target: str, port: int, timeout: int, verbose: bool) -> PortResult:
    """
    Probe NTP service on port 123.
    
    Args:
        target: Target IP address
        port: Port number (typically 123)
        timeout: Timeout in seconds
        verbose: Enable verbose output
        
    Returns:
        PortResult object
    """
    try:
        # NTP request packet (version 3, mode 3 = client)
        ntp_request = b'\x1b' + b'\x00' * 47
        
        packet = IP(dst=target) / UDP(dport=port) / Raw(load=ntp_request)
        response = sr1(packet, timeout=timeout, verbose=verbose)
        
        if response and response.haslayer(UDP):
            logger.debug(f"NTP service detected on {target}:{port}")
            return PortResult(
                port=port,
                status="open",
                service="ntp"
            )
        elif response and response.haslayer("ICMP"):
            return PortResult(port=port, status="closed")
        else:
            return PortResult(port=port, status="open|filtered", service="ntp")
            
    except Exception as e:
        logger.error(f"NTP probe failed for {target}:{port}: {e}")
        return PortResult(port=port, status="filtered")


def _probe_snmp(target: str, port: int, timeout: int, verbose: bool) -> PortResult:
    """
    Probe SNMP service on port 161.
    
    Args:
        target: Target IP address
        port: Port number (typically 161)
        timeout: Timeout in seconds
        verbose: Enable verbose output
        
    Returns:
        PortResult object
    """
    try:
        # Simple SNMP GetRequest for sysDescr
        snmp_request = (
            b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63'
            b'\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01'
            b'\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
        )
        
        packet = IP(dst=target) / UDP(dport=port) / Raw(load=snmp_request)
        response = sr1(packet, timeout=timeout, verbose=verbose)
        
        if response and response.haslayer(UDP):
            logger.debug(f"SNMP service detected on {target}:{port}")
            return PortResult(
                port=port,
                status="open",
                service="snmp"
            )
        elif response and response.haslayer("ICMP"):
            return PortResult(port=port, status="closed")
        else:
            return PortResult(port=port, status="open|filtered", service="snmp")
            
    except Exception as e:
        logger.error(f"SNMP probe failed for {target}:{port}: {e}")
        return PortResult(port=port, status="filtered")


def _probe_generic_udp(
    target: str,
    port: int,
    timeout: int,
    verbose: bool
) -> PortResult:
    """
    Probe generic UDP port.
    
    Args:
        target: Target IP address
        port: Port number
        timeout: Timeout in seconds
        verbose: Enable verbose output
        
    Returns:
        PortResult object
    """
    try:
        # Send empty UDP packet
        packet = IP(dst=target) / UDP(dport=port)
        response = sr1(packet, timeout=timeout, verbose=verbose)
        
        if response and response.haslayer("ICMP"):
            icmp_type = response["ICMP"].type
            icmp_code = response["ICMP"].code
            
            # ICMP port unreachable = closed
            if icmp_type == 3 and icmp_code == 3:
                logger.debug(f"Port {port} is CLOSED")
                return PortResult(port=port, status="closed")
            else:
                logger.debug(f"Port {port} is FILTERED (ICMP {icmp_type}/{icmp_code})")
                return PortResult(port=port, status="filtered")
        
        elif response and response.haslayer(UDP):
            logger.debug(f"Port {port} is OPEN (UDP response)")
            return PortResult(port=port, status="open")
        
        else:
            # No response = open|filtered
            logger.debug(f"Port {port} is OPEN|FILTERED (no response)")
            return PortResult(port=port, status="open|filtered")
            
    except Exception as e:
        logger.error(f"Generic UDP probe failed for {target}:{port}: {e}")
        return PortResult(port=port, status="filtered")
