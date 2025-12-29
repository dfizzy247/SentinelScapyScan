"""
Tests for SYN scanning functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from scapy.all import IP, TCP, ICMP
from SentinelScapyScan.scanners.syn_scan import syn_scan, _get_service_name
from SentinelScapyScan.models import PortResult


class TestSynScan:
    """Test cases for SYN scanner."""
    
    def test_get_service_name_known_ports(self):
        """Test service name resolution for known ports."""
        assert _get_service_name(80) == "http"
        assert _get_service_name(443) == "https"
        assert _get_service_name(22) == "ssh"
        assert _get_service_name(21) == "ftp"
        assert _get_service_name(3306) == "mysql"
    
    def test_get_service_name_unknown_port(self):
        """Test service name resolution for unknown ports."""
        assert _get_service_name(12345) == "unknown"
        assert _get_service_name(99999) == "unknown"
    
    @patch('SentinelScapyScan.scanners.syn_scan.sr')
    def test_syn_scan_open_port(self, mock_sr):
        """Test SYN scan detecting an open port."""
        # Mock SYN-ACK response (open port)
        sent_packet = IP(dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        recv_packet = IP(src="192.168.1.1") / TCP(sport=80, dport=12345, flags="SA")
        
        mock_sr.return_value = ([(sent_packet, recv_packet)], [])
        
        results = syn_scan("192.168.1.1", [80], timeout=1, verbose=False)
        
        assert len(results) == 1
        assert results[0].port == 80
        assert results[0].status == "open"
        assert results[0].service == "http"
    
    @patch('SentinelScapyScan.scanners.syn_scan.sr')
    def test_syn_scan_closed_port(self, mock_sr):
        """Test SYN scan detecting a closed port."""
        # Mock RST response (closed port)
        sent_packet = IP(dst="192.168.1.1") / TCP(sport=12345, dport=81, flags="S")
        recv_packet = IP(src="192.168.1.1") / TCP(sport=81, dport=12345, flags="RA")
        
        mock_sr.return_value = ([(sent_packet, recv_packet)], [])
        
        results = syn_scan("192.168.1.1", [81], timeout=1, verbose=False)
        
        assert len(results) == 1
        assert results[0].port == 81
        assert results[0].status == "closed"
    
    @patch('SentinelScapyScan.scanners.syn_scan.sr')
    def test_syn_scan_filtered_port(self, mock_sr):
        """Test SYN scan detecting a filtered port."""
        # Mock no response (filtered port)
        sent_packet = IP(dst="192.168.1.1") / TCP(sport=12345, dport=82, flags="S")
        
        mock_sr.return_value = ([], [sent_packet])
        
        results = syn_scan("192.168.1.1", [82], timeout=1, verbose=False)
        
        assert len(results) == 1
        assert results[0].port == 82
        assert results[0].status == "filtered"
    
    @patch('SentinelScapyScan.scanners.syn_scan.sr')
    def test_syn_scan_multiple_ports(self, mock_sr):
        """Test SYN scan with multiple ports."""
        # Mock responses for multiple ports
        sent1 = IP(dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")
        recv1 = IP(src="192.168.1.1") / TCP(sport=80, dport=12345, flags="SA")
        
        sent2 = IP(dst="192.168.1.1") / TCP(sport=12345, dport=443, flags="S")
        recv2 = IP(src="192.168.1.1") / TCP(sport=443, dport=12345, flags="SA")
        
        sent3 = IP(dst="192.168.1.1") / TCP(sport=12345, dport=8080, flags="S")
        
        mock_sr.return_value = ([(sent1, recv1), (sent2, recv2)], [sent3])
        
        results = syn_scan("192.168.1.1", [80, 443, 8080], timeout=1, verbose=False)
        
        assert len(results) == 3
        
        # Check results are sorted by port
        assert results[0].port == 80
        assert results[1].port == 443
        assert results[2].port == 8080
        
        # Check statuses
        assert results[0].status == "open"
        assert results[1].status == "open"
        assert results[2].status == "filtered"
    
    @patch('SentinelScapyScan.scanners.syn_scan.sr')
    def test_syn_scan_icmp_unreachable(self, mock_sr):
        """Test SYN scan with ICMP unreachable response."""
        sent_packet = IP(dst="192.168.1.1") / TCP(sport=12345, dport=83, flags="S")
        recv_packet = IP(src="192.168.1.1") / ICMP(type=3, code=3)
        
        mock_sr.return_value = ([(sent_packet, recv_packet)], [])
        
        results = syn_scan("192.168.1.1", [83], timeout=1, verbose=False)
        
        assert len(results) == 1
        assert results[0].port == 83
        assert results[0].status == "filtered"


class TestPortResult:
    """Test cases for PortResult model."""
    
    def test_port_result_creation(self):
        """Test creating a PortResult object."""
        result = PortResult(port=80, status="open", service="http")
        
        assert result.port == 80
        assert result.status == "open"
        assert result.service == "http"
        assert result.banner is None
    
    def test_port_result_to_dict(self):
        """Test converting PortResult to dictionary."""
        result = PortResult(
            port=443,
            status="open",
            service="https",
            banner="Apache/2.4.41"
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["port"] == 443
        assert result_dict["status"] == "open"
        assert result_dict["service"] == "https"
        assert result_dict["banner"] == "Apache/2.4.41"
