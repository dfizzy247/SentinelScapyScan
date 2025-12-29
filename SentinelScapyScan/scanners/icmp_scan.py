"""
ICMP scanner for host reachability detection.

Uses Scapy to send ICMP echo requests (ping) to determine if hosts are reachable.
"""

from typing import List, Tuple
from scapy.all import IP, ICMP, sr1
import logging

logger = logging.getLogger(__name__)


def icmp_scan(target: str, timeout: int = 2, count: int = 1) -> bool:
    """
    Perform ICMP ping to check if a host is reachable.
    
    Args:
        target: Target IP address or hostname
        timeout: Timeout in seconds for response
        count: Number of ping attempts
        
    Returns:
        True if host is reachable, False otherwise
        
    Example:
        >>> is_alive = icmp_scan("8.8.8.8")
        >>> print(is_alive)
        True
    """
    logger.debug(f"ICMP scanning {target}")
    
    try:
        for attempt in range(count):
            # Create ICMP echo request
            packet = IP(dst=target) / ICMP()
            
            # Send packet and wait for response
            response = sr1(packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(ICMP):
                    if response[ICMP].type == 0:  # Echo reply
                        logger.debug(f"Host {target} is reachable (attempt {attempt + 1}/{count})")
                        return True
        
        logger.debug(f"Host {target} is not reachable")
        return False
        
    except PermissionError:
        logger.error("ICMP scan requires root/administrator privileges")
        raise
    except Exception as e:
        logger.error(f"ICMP scan failed for {target}: {e}")
        return False


def icmp_scan_multiple(targets: List[str], timeout: int = 2) -> List[Tuple[str, bool]]:
    """
    Perform ICMP scan on multiple targets.
    
    Args:
        targets: List of IP addresses or hostnames
        timeout: Timeout in seconds for each response
        
    Returns:
        List of tuples (target, is_reachable)
        
    Example:
        >>> results = icmp_scan_multiple(["8.8.8.8", "1.1.1.1"])
        >>> print(results)
        [('8.8.8.8', True), ('1.1.1.1', True)]
    """
    results = []
    for target in targets:
        is_reachable = icmp_scan(target, timeout)
        results.append((target, is_reachable))
    
    return results
