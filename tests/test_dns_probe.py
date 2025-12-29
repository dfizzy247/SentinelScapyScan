"""
Tests for DNS probing functionality.
"""

import pytest
from unittest.mock import Mock, patch
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
from SentinelScapyScan.scanners.udp_scan import _probe_dns, udp_scan
from SentinelScapyScan.models import PortResult


class TestDNSProbe:
    """Test cases for DNS probing."""
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_dns_probe_open_port(self, mock_sr1):
        """Test DNS probe detecting an open port."""
        # Mock DNS response
        dns_response = IP(src="192.168.1.1") / UDP(sport=53) / DNS(
            id=1,
            qr=1,
            aa=0,
            rcode=0,
            qd=DNSQR(qname="version.bind"),
            an=DNSRR(rrname="version.bind", rdata="9.11.4")
        )
        
        mock_sr1.return_value = dns_response
        
        result = _probe_dns("192.168.1.1", 53, timeout=2, verbose=False)
        
        assert result.port == 53
        assert result.status == "open"
        assert result.service == "dns"
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_dns_probe_no_response(self, mock_sr1):
        """Test DNS probe with no response."""
        mock_sr1.return_value = None
        
        result = _probe_dns("192.168.1.1", 53, timeout=2, verbose=False)
        
        assert result.port == 53
        assert result.status == "open|filtered"
        assert result.service == "dns"
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_dns_probe_icmp_unreachable(self, mock_sr1):
        """Test DNS probe with ICMP unreachable."""
        from scapy.all import ICMP
        
        icmp_response = IP(src="192.168.1.1") / ICMP(type=3, code=3)
        mock_sr1.return_value = icmp_response
        
        result = _probe_dns("192.168.1.1", 53, timeout=2, verbose=False)
        
        assert result.port == 53
        assert result.status == "closed"
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_dns_probe_exception(self, mock_sr1):
        """Test DNS probe handling exceptions."""
        mock_sr1.side_effect = Exception("Network error")
        
        result = _probe_dns("192.168.1.1", 53, timeout=2, verbose=False)
        
        assert result.port == 53
        assert result.status == "filtered"


class TestUDPScan:
    """Test cases for UDP scanning."""
    
    @patch('SentinelScapyScan.scanners.udp_scan._probe_dns')
    @patch('SentinelScapyScan.scanners.udp_scan._probe_ntp')
    @patch('SentinelScapyScan.scanners.udp_scan._probe_generic_udp')
    def test_udp_scan_multiple_ports(self, mock_generic, mock_ntp, mock_dns):
        """Test UDP scan with multiple ports."""
        # Mock responses
        mock_dns.return_value = PortResult(port=53, status="open", service="dns")
        mock_ntp.return_value = PortResult(port=123, status="open", service="ntp")
        mock_generic.return_value = PortResult(port=161, status="open|filtered")
        
        results = udp_scan("192.168.1.1", [53, 123, 161], timeout=2, verbose=False)
        
        assert len(results) == 3
        assert results[0].port == 53
        assert results[0].service == "dns"
        assert results[1].port == 123
        assert results[1].service == "ntp"
        assert results[2].port == 161
    
    @patch('SentinelScapyScan.scanners.udp_scan._probe_dns')
    def test_udp_scan_dns_only(self, mock_dns):
        """Test UDP scan for DNS port only."""
        mock_dns.return_value = PortResult(port=53, status="open", service="dns")
        
        results = udp_scan("192.168.1.1", [53], timeout=2, verbose=False)
        
        assert len(results) == 1
        assert results[0].port == 53
        assert results[0].status == "open"
        assert results[0].service == "dns"
        
        # Verify DNS probe was called
        mock_dns.assert_called_once()


class TestNTPProbe:
    """Test cases for NTP probing."""
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_ntp_probe_open_port(self, mock_sr1):
        """Test NTP probe detecting an open port."""
        from SentinelScapyScan.scanners.udp_scan import _probe_ntp
        from scapy.all import Raw
        
        # Mock NTP response
        ntp_response = IP(src="192.168.1.1") / UDP(sport=123) / Raw(load=b'\x00' * 48)
        mock_sr1.return_value = ntp_response
        
        result = _probe_ntp("192.168.1.1", 123, timeout=2, verbose=False)
        
        assert result.port == 123
        assert result.status == "open"
        assert result.service == "ntp"
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_ntp_probe_no_response(self, mock_sr1):
        """Test NTP probe with no response."""
        from SentinelScapyScan.scanners.udp_scan import _probe_ntp
        
        mock_sr1.return_value = None
        
        result = _probe_ntp("192.168.1.1", 123, timeout=2, verbose=False)
        
        assert result.port == 123
        assert result.status == "open|filtered"
        assert result.service == "ntp"


class TestSNMPProbe:
    """Test cases for SNMP probing."""
    
    @patch('SentinelScapyScan.scanners.udp_scan.sr1')
    def test_snmp_probe_open_port(self, mock_sr1):
        """Test SNMP probe detecting an open port."""
        from SentinelScapyScan.scanners.udp_scan import _probe_snmp
        from scapy.all import Raw
        
        # Mock SNMP response
        snmp_response = IP(src="192.168.1.1") / UDP(sport=161) / Raw(load=b'\x30\x00')
        mock_sr1.return_value = snmp_response
        
        result = _probe_snmp("192.168.1.1", 161, timeout=2, verbose=False)
        
        assert result.port == 161
        assert result.status == "open"
        assert result.service == "snmp"
