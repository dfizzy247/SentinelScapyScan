"""
Banner grabbing module for service identification.

Connects to TCP services and retrieves banner information.
"""

import socket
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def grab_banner(
    target: str,
    port: int,
    timeout: int = 3,
    send_data: Optional[str] = None
) -> Optional[str]:
    """
    Grab banner from a TCP service.
    
    Args:
        target: Target IP address or hostname
        port: Port number
        timeout: Connection timeout in seconds
        send_data: Optional data to send before reading banner
        
    Returns:
        Banner string or None if failed
        
    Example:
        >>> banner = grab_banner("192.168.1.1", 22)
        >>> print(banner)
        'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5'
    """
    logger.debug(f"Attempting to grab banner from {target}:{port}")
    
    sock = None
    try:
        # Create socket connection
        sock = socket.create_connection(
            (target, port),
            timeout=timeout
        )
        
        # Send initial data if provided
        if send_data:
            sock.sendall(send_data.encode())
        
        # Receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if banner:
            logger.debug(f"Banner grabbed from {target}:{port}: {banner[:50]}...")
            return banner
        else:
            logger.debug(f"No banner received from {target}:{port}")
            return None
            
    except socket.timeout:
        logger.debug(f"Banner grab timeout for {target}:{port}")
        return None
    except ConnectionRefusedError:
        logger.debug(f"Connection refused for {target}:{port}")
        return None
    except Exception as e:
        logger.debug(f"Banner grab failed for {target}:{port}: {e}")
        return None
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def grab_banner_with_probe(
    target: str,
    port: int,
    timeout: int = 3
) -> Optional[str]:
    """
    Grab banner with service-specific probes.
    
    Sends appropriate probe data based on common port numbers.
    
    Args:
        target: Target IP address or hostname
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        Banner string or None if failed
    """
    # Service-specific probes
    probes = {
        21: None,  # FTP sends banner immediately
        22: None,  # SSH sends banner immediately
        25: None,  # SMTP sends banner immediately
        80: "GET / HTTP/1.0\r\n\r\n",  # HTTP
        110: None,  # POP3 sends banner immediately
        143: None,  # IMAP sends banner immediately
        443: None,  # HTTPS (requires TLS)
        3306: None,  # MySQL sends banner immediately
        5432: None,  # PostgreSQL
    }
    
    probe_data = probes.get(port)
    return grab_banner(target, port, timeout, probe_data)


def identify_service_from_banner(banner: str) -> Optional[str]:
    """
    Identify service type from banner string.
    
    Args:
        banner: Banner string
        
    Returns:
        Service name or None
        
    Example:
        >>> service = identify_service_from_banner("SSH-2.0-OpenSSH_8.2")
        >>> print(service)
        'OpenSSH'
    """
    if not banner:
        return None
    
    banner_lower = banner.lower()
    
    # SSH
    if banner.startswith("SSH-"):
        if "openssh" in banner_lower:
            return "OpenSSH"
        return "SSH"
    
    # HTTP
    if banner.startswith("HTTP/"):
        return "HTTP"
    
    # FTP
    if "ftp" in banner_lower:
        return "FTP"
    
    # SMTP
    if "smtp" in banner_lower or banner.startswith("220"):
        return "SMTP"
    
    # MySQL
    if "mysql" in banner_lower:
        return "MySQL"
    
    # PostgreSQL
    if "postgresql" in banner_lower:
        return "PostgreSQL"
    
    # Apache
    if "apache" in banner_lower:
        return "Apache"
    
    # Nginx
    if "nginx" in banner_lower:
        return "Nginx"
    
    # Microsoft IIS
    if "microsoft" in banner_lower and "iis" in banner_lower:
        return "Microsoft IIS"
    
    return None
