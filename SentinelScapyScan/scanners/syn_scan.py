"""
SYN scanner for TCP port scanning.

Uses Scapy to perform SYN scans (stealth scans) to detect open, closed, and filtered ports.
"""

from typing import List
from scapy.all import IP, TCP, sr
import logging
import random
from SentinelScapyScan.models import PortResult

logger = logging.getLogger(__name__)


def syn_scan(
    target: str,
    ports: List[int],
    timeout: int = 2,
    verbose: bool = False
) -> List[PortResult]:
    """
    Perform SYN scan on specified ports.
    
    Args:
        target: Target IP address or hostname
        ports: List of ports to scan
        timeout: Timeout in seconds for responses
        verbose: Enable verbose output
        
    Returns:
        List of PortResult objects
        
    Example:
        >>> results = syn_scan("192.168.1.1", [22, 80, 443])
        >>> for result in results:
        ...     print(f"Port {result.port}: {result.status}")
    """
    logger.info(f"Starting SYN scan on {target} for {len(ports)} ports")
    
    results = []
    
    try:
        # Create SYN packets for all ports
        packets = []
        
        for port in ports:
            # Generate a random source port (1024-65535)
            src_port = random.randint(1024, 65535)
            packet = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
            packets.append(packet)
        
        # Send packets and receive responses
        answered, unanswered = sr(
            packets,
            timeout=timeout,
            verbose=verbose,
            retry=1
        )
        
        # Process answered packets
        answered_ports = set()
        for sent, received in answered:
            port = sent[TCP].dport
            answered_ports.add(port)
            
            if received.haslayer(TCP):
                tcp_layer = received[TCP]
                
                # RST or RST-ACK response = closed port (check first)
                if tcp_layer.flags & 0x04:  # RST flag set
                    results.append(PortResult(
                        port=port,
                        status="closed"
                    ))
                    logger.debug(f"Port {port} is CLOSED")
                
                # SYN-ACK response = open port
                elif tcp_layer.flags & 0x12:  # SYN-ACK
                    results.append(PortResult(
                        port=port,
                        status="open",
                        service=_get_service_name(port)
                    ))
                    logger.debug(f"Port {port} is OPEN")
                    
                    # Send RST to close connection
                    # Use the received packet's destination port as our source port
                    rst_packet = IP(dst=target) / TCP(
                        sport=received[TCP].dport,
                        dport=port,
                        flags="R"
                    )
                    sr(rst_packet, timeout=1, verbose=False)
            
            # ICMP unreachable = filtered
            elif received.haslayer("ICMP"):
                results.append(PortResult(
                    port=port,
                    status="filtered"
                ))
                logger.debug(f"Port {port} is FILTERED")
        
        # Process unanswered packets (filtered)
        for sent in unanswered:
            port = sent[TCP].dport
            if port not in answered_ports:
                results.append(PortResult(
                    port=port,
                    status="filtered"
                ))
                logger.debug(f"Port {port} is FILTERED (no response)")
        
        logger.info(f"SYN scan completed. Scanned {len(ports)} ports")
        return sorted(results, key=lambda x: x.port)
        
    except PermissionError:
        logger.error("SYN scan requires root/administrator privileges")
        raise
    except Exception as e:
        logger.error(f"SYN scan failed: {e}")
        raise


def _get_service_name(port: int) -> str:
    """
    Get common service name for a port number.
    
    Args:
        port: Port number
        
    Returns:
        Service name or "unknown"
    """
    common_services = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        27017: "mongodb",
    }
    
    return common_services.get(port, "unknown")
