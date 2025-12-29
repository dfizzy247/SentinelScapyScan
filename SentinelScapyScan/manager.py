"""
Scan manager for orchestrating network scans and fingerprinting.

Coordinates reachability checks, port scanning, and service fingerprinting.
"""

import asyncio
import logging
from typing import List, Optional
from datetime import datetime
import time

from SentinelScapyScan.models import HostResult, PortResult
from SentinelScapyScan.scanners.icmp_scan import icmp_scan
from SentinelScapyScan.scanners.syn_scan import syn_scan
from SentinelScapyScan.scanners.udp_scan import udp_scan
from SentinelScapyScan.fingerprinting.banner import grab_banner_with_probe
from SentinelScapyScan.fingerprinting.http_fp import fingerprint_http_sync
from SentinelScapyScan.fingerprinting.tls_fp import fingerprint_tls

logger = logging.getLogger(__name__)


class ScanManager:
    """
    Manages the complete scanning workflow for a target host.
    
    Coordinates:
    - Reachability checks (ICMP)
    - Port scanning (SYN, UDP)
    - Service fingerprinting (banner, HTTP, TLS)
    """
    
    def __init__(
        self,
        timeout: int = 3,
        enable_udp: bool = False,
        enable_fingerprinting: bool = True,
        max_concurrent_fingerprints: int = 10
    ):
        """
        Initialize scan manager.
        
        Args:
            timeout: Default timeout for operations
            enable_udp: Enable UDP scanning
            enable_fingerprinting: Enable service fingerprinting
            max_concurrent_fingerprints: Maximum concurrent fingerprinting tasks
        """
        self.timeout = timeout
        self.enable_udp = enable_udp
        self.enable_fingerprinting = enable_fingerprinting
        self.max_concurrent_fingerprints = max_concurrent_fingerprints
    
    def scan_host(
        self,
        target: str,
        ports: List[int],
        skip_ping: bool = False
    ) -> HostResult:
        """
        Perform complete scan of a single host.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            skip_ping: Skip reachability check
            
        Returns:
            HostResult object with complete scan data
        """
        logger.info(f"Starting scan of host: {target}")
        start_time = time.time()
        
        # Step 1: Reachability check
        if not skip_ping:
            logger.info(f"Checking reachability of {target}")
            reachable = icmp_scan(target, timeout=self.timeout)
        else:
            logger.info(f"Skipping reachability check for {target}")
            reachable = True
        
        # Initialize host result
        host_result = HostResult(
            ip=target,
            reachable=reachable,
            scan_time=datetime.now()
        )
        
        if not reachable and not skip_ping:
            logger.warning(f"Host {target} is not reachable")
            host_result.scan_duration = time.time() - start_time
            return host_result
        
        # Step 2: TCP SYN scan
        logger.info(f"Performing SYN scan on {target} ({len(ports)} ports)")
        try:
            tcp_results = syn_scan(target, ports, timeout=self.timeout)
            host_result.ports.extend(tcp_results)
        except Exception as e:
            logger.error(f"SYN scan failed for {target}: {e}")
        
        # Step 3: UDP scan (if enabled)
        if self.enable_udp:
            logger.info(f"Performing UDP scan on {target}")
            udp_ports = [53, 123, 161, 162, 514]  # Common UDP ports
            try:
                udp_results = udp_scan(target, udp_ports, timeout=self.timeout)
                host_result.ports.extend(udp_results)
            except Exception as e:
                logger.error(f"UDP scan failed for {target}: {e}")
        
        # Step 4: Fingerprinting (if enabled)
        if self.enable_fingerprinting:
            logger.info(f"Starting fingerprinting for {target}")
            self._fingerprint_services(host_result)
        
        # Calculate scan duration
        host_result.scan_duration = time.time() - start_time
        logger.info(
            f"Scan completed for {target} in {host_result.scan_duration:.2f}s "
            f"({len(host_result.get_open_ports())} open ports)"
        )
        
        return host_result
    
    def _fingerprint_services(self, host_result: HostResult) -> None:
        """
        Fingerprint services on open ports.
        
        Args:
            host_result: HostResult object to update with fingerprint data
        """
        open_ports = host_result.get_open_ports()
        
        if not open_ports:
            logger.debug("No open ports to fingerprint")
            return
        
        logger.info(f"Fingerprinting {len(open_ports)} open ports")
        
        # Run fingerprinting tasks
        for port_result in open_ports:
            try:
                self._fingerprint_port(host_result.ip, port_result)
            except Exception as e:
                logger.error(
                    f"Fingerprinting failed for {host_result.ip}:{port_result.port}: {e}"
                )
    
    def _fingerprint_port(self, target: str, port_result: PortResult) -> None:
        """
        Fingerprint a single port.
        
        Args:
            target: Target IP address
            port_result: PortResult object to update
        """
        port = port_result.port
        
        # Banner grabbing
        logger.debug(f"Grabbing banner from {target}:{port}")
        banner = grab_banner_with_probe(target, port, timeout=self.timeout)
        if banner:
            port_result.banner = banner
        
        # HTTP fingerprinting
        if port in [80, 8080, 8000, 8888]:
            logger.debug(f"Fingerprinting HTTP on {target}:{port}")
            http_info = fingerprint_http_sync(
                target, port, use_https=False, timeout=self.timeout
            )
            if http_info:
                port_result.http_headers = http_info
        
        # HTTPS fingerprinting
        elif port in [443, 8443]:
            logger.debug(f"Fingerprinting HTTPS on {target}:{port}")
            
            # HTTP fingerprinting
            http_info = fingerprint_http_sync(
                target, port, use_https=True, timeout=self.timeout
            )
            if http_info:
                port_result.http_headers = http_info
            
            # TLS fingerprinting
            tls_info = fingerprint_tls(target, port, timeout=self.timeout)
            if tls_info:
                port_result.tls_info = tls_info
    
    async def scan_host_async(
        self,
        target: str,
        ports: List[int],
        skip_ping: bool = False
    ) -> HostResult:
        """
        Asynchronous version of scan_host.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            skip_ping: Skip reachability check
            
        Returns:
            HostResult object with complete scan data
        """
        logger.info(f"Starting async scan of host: {target}")
        start_time = time.time()
        
        # Reachability check (synchronous)
        if not skip_ping:
            reachable = await asyncio.to_thread(
                icmp_scan, target, timeout=self.timeout
            )
        else:
            reachable = True
        
        host_result = HostResult(
            ip=target,
            reachable=reachable,
            scan_time=datetime.now()
        )
        
        if not reachable and not skip_ping:
            logger.warning(f"Host {target} is not reachable")
            host_result.scan_duration = time.time() - start_time
            return host_result
        
        # TCP SYN scan (synchronous)
        try:
            tcp_results = await asyncio.to_thread(
                syn_scan, target, ports, self.timeout
            )
            host_result.ports.extend(tcp_results)
        except Exception as e:
            logger.error(f"SYN scan failed for {target}: {e}")
        
        # UDP scan (if enabled)
        if self.enable_udp:
            udp_ports = [53, 123, 161, 162, 514]
            try:
                udp_results = await asyncio.to_thread(
                    udp_scan, target, udp_ports, self.timeout
                )
                host_result.ports.extend(udp_results)
            except Exception as e:
                logger.error(f"UDP scan failed for {target}: {e}")
        
        # Fingerprinting (if enabled)
        if self.enable_fingerprinting:
            await self._fingerprint_services_async(host_result)
        
        host_result.scan_duration = time.time() - start_time
        logger.info(
            f"Async scan completed for {target} in {host_result.scan_duration:.2f}s"
        )
        
        return host_result
    
    async def _fingerprint_services_async(self, host_result: HostResult) -> None:
        """
        Asynchronously fingerprint services on open ports.
        
        Args:
            host_result: HostResult object to update
        """
        open_ports = host_result.get_open_ports()
        
        if not open_ports:
            return
        
        logger.info(f"Async fingerprinting {len(open_ports)} open ports")
        
        # Create fingerprinting tasks
        tasks = []
        for port_result in open_ports:
            task = asyncio.create_task(
                self._fingerprint_port_async(host_result.ip, port_result)
            )
            tasks.append(task)
        
        # Run tasks with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent_fingerprints)
        
        async def bounded_task(task):
            async with semaphore:
                return await task
        
        await asyncio.gather(*[bounded_task(task) for task in tasks])
    
    async def _fingerprint_port_async(
        self,
        target: str,
        port_result: PortResult
    ) -> None:
        """
        Asynchronously fingerprint a single port.
        
        Args:
            target: Target IP address
            port_result: PortResult object to update
        """
        port = port_result.port
        
        # Banner grabbing
        banner = await asyncio.to_thread(
            grab_banner_with_probe, target, port, self.timeout
        )
        if banner:
            port_result.banner = banner
        
        # HTTP/HTTPS fingerprinting
        if port in [80, 8080, 8000, 8888]:
            http_info = await asyncio.to_thread(
                fingerprint_http_sync, target, port, False, self.timeout
            )
            if http_info:
                port_result.http_headers = http_info
        
        elif port in [443, 8443]:
            http_info = await asyncio.to_thread(
                fingerprint_http_sync, target, port, True, self.timeout
            )
            if http_info:
                port_result.http_headers = http_info
            
            tls_info = await asyncio.to_thread(
                fingerprint_tls, target, port, self.timeout
            )
            if tls_info:
                port_result.tls_info = tls_info
