"""
Configuration management module.

Handles loading and managing scan configuration.
"""

import yaml
import toml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


def get_default_config() -> Dict[str, Any]:
    """
    Get default configuration.
    
    Returns:
        Dictionary containing default configuration
    """
    return {
        "scan": {
            "timeout": 3,
            "retry_count": 2,
            "max_concurrent_scans": 10,
            "enable_udp": False,
            "enable_fingerprinting": True,
            "skip_ping": False,
        },
        "ports": {
            "default_tcp_ports": [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5900, 8080, 8443
            ],
            "default_udp_ports": [53, 123, 161, 162, 514],
            "common_ports": list(range(1, 1025)),  # Well-known ports
            "all_ports": list(range(1, 65536)),  # All ports
        },
        "fingerprinting": {
            "grab_banners": True,
            "http_fingerprint": True,
            "tls_fingerprint": True,
            "max_concurrent_fingerprints": 10,
        },
        "reporting": {
            "output_dir": "reports",
            "generate_json": True,
            "generate_html": True,
            "generate_csv": False,
            "pretty_json": True,
        },
        "logging": {
            "level": "INFO",
            "log_to_file": True,
            "log_file": "logs/sentinelscapyscan.log",
            "max_log_size": 10485760,  # 10 MB
            "backup_count": 5,
        }
    }


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML or TOML file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing configuration
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config file format is unsupported
    """
    logger.info(f"Loading configuration from {config_path}")
    
    config_file = Path(config_path)
    
    if not config_file.exists():
        logger.error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    # Determine file format
    suffix = config_file.suffix.lower()
    
    try:
        if suffix in ['.yaml', '.yml']:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        elif suffix == '.toml':
            with open(config_file, 'r', encoding='utf-8') as f:
                config = toml.load(f)
        else:
            raise ValueError(f"Unsupported config file format: {suffix}")
        
        # Merge with defaults
        default_config = get_default_config()
        merged_config = _merge_configs(default_config, config)
        
        logger.info(f"Configuration loaded successfully from {config_path}")
        return merged_config
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise


def _merge_configs(default: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge custom configuration with defaults.
    
    Args:
        default: Default configuration
        custom: Custom configuration
        
    Returns:
        Merged configuration
    """
    merged = default.copy()
    
    for key, value in custom.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_configs(merged[key], value)
        else:
            merged[key] = value
    
    return merged


def save_config(config: Dict[str, Any], output_path: str, format: str = 'yaml') -> None:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary
        output_path: Path to output file
        format: Output format ('yaml' or 'toml')
    """
    logger.info(f"Saving configuration to {output_path}")
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        if format == 'yaml':
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        elif format == 'toml':
            with open(output_file, 'w', encoding='utf-8') as f:
                toml.dump(config, f)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Configuration saved successfully to {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")
        raise


def get_port_list(config: Dict[str, Any], port_spec: Optional[str] = None) -> List[int]:
    """
    Get list of ports to scan based on configuration and specification.
    
    Args:
        config: Configuration dictionary
        port_spec: Port specification string (e.g., "80,443,8080-8090" or "common" or "all")
        
    Returns:
        List of port numbers
    """
    if port_spec is None:
        # Use default TCP ports from config
        return config.get("ports", {}).get("default_tcp_ports", [80, 443])
    
    # Handle predefined port lists
    if port_spec.lower() == "common":
        return config.get("ports", {}).get("common_ports", list(range(1, 1025)))
    elif port_spec.lower() == "all":
        return config.get("ports", {}).get("all_ports", list(range(1, 65536)))
    elif port_spec.lower() == "default":
        return config.get("ports", {}).get("default_tcp_ports", [80, 443])
    
    # Parse custom port specification
    ports = []
    
    for part in port_spec.split(','):
        part = part.strip()
        
        if '-' in part:
            # Port range (e.g., "8080-8090")
            try:
                start, end = part.split('-')
                start = int(start.strip())
                end = int(end.strip())
                ports.extend(range(start, end + 1))
            except ValueError:
                logger.warning(f"Invalid port range: {part}")
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    logger.warning(f"Port out of range: {port}")
            except ValueError:
                logger.warning(f"Invalid port number: {part}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        True if valid, False otherwise
    """
    required_keys = ["scan", "ports", "fingerprinting", "reporting", "logging"]
    
    for key in required_keys:
        if key not in config:
            logger.error(f"Missing required configuration section: {key}")
            return False
    
    # Validate scan settings
    scan_config = config.get("scan", {})
    if scan_config.get("timeout", 0) <= 0:
        logger.error("Invalid timeout value")
        return False
    
    if scan_config.get("max_concurrent_scans", 0) <= 0:
        logger.error("Invalid max_concurrent_scans value")
        return False
    
    return True
