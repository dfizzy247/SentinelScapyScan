"""
TLS/SSL fingerprinting module.

Extracts TLS certificate information and connection details.
"""

import ssl
import socket
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def fingerprint_tls(
    target: str,
    port: int = 443,
    timeout: int = 5
) -> Optional[Dict[str, Any]]:
    """
    Fingerprint TLS/SSL service and extract certificate information.
    
    Args:
        target: Target IP address or hostname
        port: Port number (default: 443)
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary containing TLS fingerprint data or None if failed
        
    Example:
        >>> result = fingerprint_tls("example.com", 443)
        >>> print(result['tls_version'])
        'TLSv1.3'
        >>> print(result['issuer'])
        {'CN': 'DigiCert TLS RSA SHA256 2020 CA1', ...}
    """
    logger.debug(f"Fingerprinting TLS service at {target}:{port}")
    
    sock = None
    ssl_sock = None
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Create socket connection
        sock = socket.create_connection((target, port), timeout=timeout)
        
        # Wrap socket with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=target)
        
        # Get certificate
        cert = ssl_sock.getpeercert()
        
        # Get TLS version
        tls_version = ssl_sock.version()
        
        # Get cipher suite
        cipher = ssl_sock.cipher()
        
        # Extract certificate information
        fingerprint = {
            "tls_version": tls_version,
            "cipher_suite": {
                "name": cipher[0] if cipher else None,
                "protocol": cipher[1] if cipher else None,
                "bits": cipher[2] if cipher else None,
            },
            "certificate": _extract_certificate_info(cert) if cert else None,
        }
        
        logger.debug(f"TLS fingerprint completed for {target}:{port}")
        return fingerprint
        
    except ssl.SSLError as e:
        logger.debug(f"SSL error for {target}:{port}: {e}")
        return None
    except socket.timeout:
        logger.debug(f"TLS connection timeout for {target}:{port}")
        return None
    except ConnectionRefusedError:
        logger.debug(f"TLS connection refused for {target}:{port}")
        return None
    except Exception as e:
        logger.debug(f"TLS fingerprinting failed for {target}:{port}: {e}")
        return None
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except:
                pass
        if sock:
            try:
                sock.close()
            except:
                pass


def _extract_certificate_info(cert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract relevant information from SSL certificate.
    
    Args:
        cert: Certificate dictionary from getpeercert()
        
    Returns:
        Dictionary of certificate information
    """
    cert_info = {}
    
    # Subject
    if "subject" in cert:
        subject = {}
        for item in cert["subject"]:
            for key, value in item:
                subject[key] = value
        cert_info["subject"] = subject
    
    # Issuer
    if "issuer" in cert:
        issuer = {}
        for item in cert["issuer"]:
            for key, value in item:
                issuer[key] = value
        cert_info["issuer"] = issuer
    
    # Version
    if "version" in cert:
        cert_info["version"] = cert["version"]
    
    # Serial number
    if "serialNumber" in cert:
        cert_info["serial_number"] = cert["serialNumber"]
    
    # Validity period
    if "notBefore" in cert:
        try:
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            cert_info["not_before"] = not_before.isoformat()
        except:
            cert_info["not_before"] = cert["notBefore"]
    
    if "notAfter" in cert:
        try:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            cert_info["not_after"] = not_after.isoformat()
            
            # Check if certificate is expired
            if not_after < datetime.now():
                cert_info["expired"] = True
            else:
                cert_info["expired"] = False
                days_until_expiry = (not_after - datetime.now()).days
                cert_info["days_until_expiry"] = days_until_expiry
        except:
            cert_info["not_after"] = cert["notAfter"]
    
    # Subject Alternative Names (SANs)
    if "subjectAltName" in cert:
        sans = []
        for san_type, san_value in cert["subjectAltName"]:
            sans.append({"type": san_type, "value": san_value})
        cert_info["subject_alt_names"] = sans
    
    # OCSP
    if "OCSP" in cert:
        cert_info["ocsp"] = cert["OCSP"]
    
    # CA Issuers
    if "caIssuers" in cert:
        cert_info["ca_issuers"] = cert["caIssuers"]
    
    # CRL Distribution Points
    if "crlDistributionPoints" in cert:
        cert_info["crl_distribution_points"] = cert["crlDistributionPoints"]
    
    return cert_info


def check_tls_vulnerabilities(fingerprint: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check for common TLS vulnerabilities and misconfigurations.
    
    Args:
        fingerprint: TLS fingerprint dictionary
        
    Returns:
        Dictionary of vulnerability findings
    """
    vulnerabilities = {
        "issues": [],
        "warnings": [],
        "info": []
    }
    
    # Check TLS version
    tls_version = fingerprint.get("tls_version", "")
    if tls_version in ["SSLv2", "SSLv3"]:
        vulnerabilities["issues"].append(
            f"Insecure protocol version: {tls_version}"
        )
    elif tls_version == "TLSv1.0":
        vulnerabilities["warnings"].append(
            "Deprecated protocol version: TLSv1.0"
        )
    elif tls_version == "TLSv1.1":
        vulnerabilities["warnings"].append(
            "Deprecated protocol version: TLSv1.1"
        )
    
    # Check cipher suite
    cipher = fingerprint.get("cipher_suite", {})
    cipher_name = cipher.get("name", "").upper()
    
    if "NULL" in cipher_name or "ANON" in cipher_name:
        vulnerabilities["issues"].append(
            f"Insecure cipher suite: {cipher_name}"
        )
    elif "RC4" in cipher_name:
        vulnerabilities["issues"].append(
            f"Weak cipher suite (RC4): {cipher_name}"
        )
    elif "DES" in cipher_name and "3DES" not in cipher_name:
        vulnerabilities["issues"].append(
            f"Weak cipher suite (DES): {cipher_name}"
        )
    elif "3DES" in cipher_name:
        vulnerabilities["warnings"].append(
            f"Deprecated cipher suite (3DES): {cipher_name}"
        )
    
    # Check certificate
    cert = fingerprint.get("certificate", {})
    
    if cert.get("expired"):
        vulnerabilities["issues"].append("Certificate is expired")
    
    days_until_expiry = cert.get("days_until_expiry")
    if days_until_expiry is not None:
        if days_until_expiry < 30:
            vulnerabilities["warnings"].append(
                f"Certificate expires in {days_until_expiry} days"
            )
    
    # Check key size
    cipher_bits = cipher.get("bits")
    if cipher_bits and cipher_bits < 128:
        vulnerabilities["issues"].append(
            f"Weak key size: {cipher_bits} bits"
        )
    
    return vulnerabilities
