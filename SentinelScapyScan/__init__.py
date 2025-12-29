"""
SentinelScapyScan - A modular cybersecurity automation suite.

This package provides network scanning, service fingerprinting, and reporting capabilities.
"""

__version__ = "0.1.0"
__author__ = "SentinelScapyScan Team"

from SentinelScapyScan.models import HostResult, PortResult

__all__ = ["HostResult", "PortResult", "__version__"]
