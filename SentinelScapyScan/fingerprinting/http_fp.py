"""
HTTP fingerprinting module.

Extracts HTTP headers and security information from web servers.
"""

import httpx
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


async def fingerprint_http(
    target: str,
    port: int = 80,
    use_https: bool = False,
    timeout: int = 5
) -> Optional[Dict[str, Any]]:
    """
    Fingerprint HTTP service and extract headers.
    
    Args:
        target: Target IP address or hostname
        port: Port number (default: 80)
        use_https: Use HTTPS instead of HTTP
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing HTTP fingerprint data or None if failed
        
    Example:
        >>> import asyncio
        >>> result = asyncio.run(fingerprint_http("example.com", 443, use_https=True))
        >>> print(result['server'])
        'nginx/1.18.0'
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}:{port}/"
    
    logger.debug(f"Fingerprinting HTTP service at {url}")
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            response = await client.get(url, follow_redirects=False)
            
            fingerprint = {
                "url": url,
                "status_code": response.status_code,
                "server": response.headers.get("Server"),
                "powered_by": response.headers.get("X-Powered-By"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
                "headers": dict(response.headers),
            }
            
            # Extract security headers
            security_headers = _extract_security_headers(response.headers)
            fingerprint["security_headers"] = security_headers
            
            # Extract cookies
            cookies = _extract_cookies(response.cookies)
            if cookies:
                fingerprint["cookies"] = cookies
            
            # Detect technologies
            technologies = _detect_technologies(response)
            if technologies:
                fingerprint["technologies"] = technologies
            
            logger.debug(f"HTTP fingerprint completed for {url}")
            return fingerprint
            
    except httpx.TimeoutException:
        logger.debug(f"HTTP request timeout for {url}")
        return None
    except httpx.ConnectError:
        logger.debug(f"HTTP connection failed for {url}")
        return None
    except Exception as e:
        logger.debug(f"HTTP fingerprinting failed for {url}: {e}")
        return None


def _extract_security_headers(headers: httpx.Headers) -> Dict[str, Any]:
    """
    Extract security-related HTTP headers.
    
    Args:
        headers: HTTP response headers
        
    Returns:
        Dictionary of security headers
    """
    security_headers = {}
    
    # Content Security Policy
    csp = headers.get("Content-Security-Policy")
    if csp:
        security_headers["csp"] = csp
    
    # CORS headers
    cors_headers = {
        "access_control_allow_origin": headers.get("Access-Control-Allow-Origin"),
        "access_control_allow_methods": headers.get("Access-Control-Allow-Methods"),
        "access_control_allow_headers": headers.get("Access-Control-Allow-Headers"),
        "access_control_allow_credentials": headers.get("Access-Control-Allow-Credentials"),
    }
    
    # Filter out None values
    cors_headers = {k: v for k, v in cors_headers.items() if v is not None}
    if cors_headers:
        security_headers["cors"] = cors_headers
    
    # Other security headers
    if headers.get("Strict-Transport-Security"):
        security_headers["hsts"] = headers.get("Strict-Transport-Security")
    
    if headers.get("X-Frame-Options"):
        security_headers["x_frame_options"] = headers.get("X-Frame-Options")
    
    if headers.get("X-Content-Type-Options"):
        security_headers["x_content_type_options"] = headers.get("X-Content-Type-Options")
    
    if headers.get("X-XSS-Protection"):
        security_headers["x_xss_protection"] = headers.get("X-XSS-Protection")
    
    if headers.get("Referrer-Policy"):
        security_headers["referrer_policy"] = headers.get("Referrer-Policy")
    
    if headers.get("Permissions-Policy"):
        security_headers["permissions_policy"] = headers.get("Permissions-Policy")
    
    return security_headers


def _extract_cookies(cookies: httpx.Cookies) -> Optional[Dict[str, Any]]:
    """
    Extract cookie information.
    
    Args:
        cookies: HTTP response cookies
        
    Returns:
        Dictionary of cookie information or None
    """
    if not cookies:
        return None
    
    cookie_info = {}
    for name, value in cookies.items():
        cookie_info[name] = {
            "value": value,
            "length": len(value)
        }
    
    return cookie_info


def _detect_technologies(response: httpx.Response) -> Optional[Dict[str, str]]:
    """
    Detect web technologies from response.
    
    Args:
        response: HTTP response object
        
    Returns:
        Dictionary of detected technologies or None
    """
    technologies = {}
    
    headers = response.headers
    content = response.text if hasattr(response, 'text') else ""
    
    # Server detection
    server = headers.get("Server", "").lower()
    if "apache" in server:
        technologies["web_server"] = "Apache"
    elif "nginx" in server:
        technologies["web_server"] = "Nginx"
    elif "iis" in server:
        technologies["web_server"] = "Microsoft IIS"
    elif "lighttpd" in server:
        technologies["web_server"] = "Lighttpd"
    
    # Framework detection
    powered_by = headers.get("X-Powered-By", "").lower()
    if "php" in powered_by:
        technologies["language"] = "PHP"
    elif "asp.net" in powered_by:
        technologies["framework"] = "ASP.NET"
    
    # Content-based detection
    if content:
        content_lower = content.lower()
        
        if "wordpress" in content_lower or "wp-content" in content_lower:
            technologies["cms"] = "WordPress"
        elif "joomla" in content_lower:
            technologies["cms"] = "Joomla"
        elif "drupal" in content_lower:
            technologies["cms"] = "Drupal"
        
        if "react" in content_lower or "reactjs" in content_lower:
            technologies["frontend"] = "React"
        elif "vue" in content_lower or "vuejs" in content_lower:
            technologies["frontend"] = "Vue.js"
        elif "angular" in content_lower:
            technologies["frontend"] = "Angular"
    
    return technologies if technologies else None


def fingerprint_http_sync(
    target: str,
    port: int = 80,
    use_https: bool = False,
    timeout: int = 5
) -> Optional[Dict[str, Any]]:
    """
    Synchronous version of fingerprint_http.
    
    Args:
        target: Target IP address or hostname
        port: Port number (default: 80)
        use_https: Use HTTPS instead of HTTP
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing HTTP fingerprint data or None if failed
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}:{port}/"
    
    logger.debug(f"Fingerprinting HTTP service at {url}")
    
    try:
        with httpx.Client(verify=False, timeout=timeout) as client:
            response = client.get(url, follow_redirects=False)
            
            fingerprint = {
                "url": url,
                "status_code": response.status_code,
                "server": response.headers.get("Server"),
                "powered_by": response.headers.get("X-Powered-By"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
                "headers": dict(response.headers),
            }
            
            security_headers = _extract_security_headers(response.headers)
            fingerprint["security_headers"] = security_headers
            
            cookies = _extract_cookies(response.cookies)
            if cookies:
                fingerprint["cookies"] = cookies
            
            technologies = _detect_technologies(response)
            if technologies:
                fingerprint["technologies"] = technologies
            
            logger.debug(f"HTTP fingerprint completed for {url}")
            return fingerprint
            
    except Exception as e:
        logger.debug(f"HTTP fingerprinting failed for {url}: {e}")
        return None
