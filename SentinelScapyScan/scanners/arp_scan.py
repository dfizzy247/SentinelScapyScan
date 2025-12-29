"""
ARP scanner for local network host discovery.

Uses Scapy to send ARP requests and discover active hosts on the local network.
"""

from typing import List
from scapy.all import ARP, Ether, srp
import logging

logger = logging.getLogger(__name__)


def arp_scan(network: str, timeout: int = 2, verbose: bool = False) -> List[str]:
    """
    Perform ARP scan to discover active hosts on local network.
    
    Args:
        network: Network range in CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout in seconds for responses
        verbose: Enable verbose output
        
    Returns:
        List of active IP addresses
        
    Example:
        >>> hosts = arp_scan("192.168.1.0/24")
        >>> print(hosts)
        ['192.168.1.1', '192.168.1.100', '192.168.1.254']
    """
    logger.info(f"Starting ARP scan on network: {network}")
    
    try:
        # Create ARP request packet
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send packet and receive responses
        answered, _ = srp(
            arp_request_broadcast,
            timeout=timeout,
            verbose=verbose,
            retry=2
        )
        
        # Extract IP addresses from responses
        active_hosts = []
        for sent, received in answered:
            active_hosts.append(received.psrc)
            logger.debug(f"Host discovered: {received.psrc} (MAC: {received.hwsrc})")
        
        logger.info(f"ARP scan completed. Found {len(active_hosts)} active hosts")
        return active_hosts
        
    except PermissionError:
        logger.error("ARP scan requires root/administrator privileges")
        raise
    except Exception as e:
        logger.error(f"ARP scan failed: {e}")
        raise
