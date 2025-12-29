"""
Tests for report generation functionality.
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from SentinelScapyScan.models import HostResult, PortResult
from SentinelScapyScan.reporting.json_writer import write_json_report, load_json_report, export_to_csv
from SentinelScapyScan.reporting.html_report import generate_html_report


class TestJSONReportGeneration:
    """Test cases for JSON report generation."""
    
    def test_write_json_report(self, tmp_path):
        """Test writing JSON report to file."""
        # Create mock results
        port1 = PortResult(port=80, status="open", service="http", banner="Apache/2.4.41")
        port2 = PortResult(port=443, status="open", service="https")
        
        host = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[port1, port2],
            scan_time=datetime.now(),
            scan_duration=5.5
        )
        
        # Write report
        output_path = tmp_path / "test_report.json"
        write_json_report([host], str(output_path))
        
        # Verify file exists
        assert output_path.exists()
        
        # Load and verify content
        with open(output_path, 'r') as f:
            report = json.load(f)
        
        assert "metadata" in report
        assert "results" in report
        assert "statistics" in report
        assert report["metadata"]["total_hosts"] == 1
        assert report["metadata"]["total_open_ports"] == 2
        assert len(report["results"]) == 1
        assert report["results"][0]["ip"] == "192.168.1.1"
        assert report["results"][0]["reachable"] is True
        assert len(report["results"][0]["ports"]) == 2
    
    def test_load_json_report(self, tmp_path):
        """Test loading JSON report from file."""
        # Create and write report
        port = PortResult(port=22, status="open", service="ssh")
        host = HostResult(
            ip="10.0.0.1",
            reachable=True,
            ports=[port],
            scan_time=datetime.now(),
            scan_duration=3.2
        )
        
        output_path = tmp_path / "load_test.json"
        write_json_report([host], str(output_path))
        
        # Load report
        loaded_report = load_json_report(str(output_path))
        
        assert loaded_report is not None
        assert "results" in loaded_report
        assert loaded_report["results"][0]["ip"] == "10.0.0.1"
    
    def test_json_report_statistics(self, tmp_path):
        """Test statistics in JSON report."""
        # Create multiple hosts with different port statuses
        host1 = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[
                PortResult(port=80, status="open", service="http"),
                PortResult(port=443, status="open", service="https"),
                PortResult(port=8080, status="closed"),
            ],
            scan_time=datetime.now(),
            scan_duration=4.0
        )
        
        host2 = HostResult(
            ip="192.168.1.2",
            reachable=False,
            ports=[],
            scan_time=datetime.now(),
            scan_duration=1.0
        )
        
        output_path = tmp_path / "stats_test.json"
        write_json_report([host1, host2], str(output_path))
        
        with open(output_path, 'r') as f:
            report = json.load(f)
        
        stats = report["statistics"]
        assert stats["total_hosts_scanned"] == 2
        assert stats["reachable_hosts"] == 1
        assert stats["unreachable_hosts"] == 1
        assert stats["total_open_ports"] == 2
        assert stats["total_closed_ports"] == 1
    
    def test_json_report_with_config(self, tmp_path):
        """Test JSON report with configuration."""
        host = HostResult(ip="192.168.1.1", reachable=True)
        
        config = {
            "scan": {"timeout": 3},
            "ports": {"default_tcp_ports": [80, 443]}
        }
        
        output_path = tmp_path / "config_test.json"
        write_json_report([host], str(output_path), config=config)
        
        with open(output_path, 'r') as f:
            report = json.load(f)
        
        assert "scan_configuration" in report
        assert report["scan_configuration"]["scan"]["timeout"] == 3


class TestCSVExport:
    """Test cases for CSV export."""
    
    def test_export_to_csv(self, tmp_path):
        """Test exporting results to CSV."""
        port1 = PortResult(port=80, status="open", service="http", banner="Apache")
        port2 = PortResult(port=443, status="open", service="https")
        
        host = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[port1, port2]
        )
        
        output_path = tmp_path / "test_export.csv"
        export_to_csv([host], str(output_path))
        
        assert output_path.exists()
        
        # Read and verify CSV content
        with open(output_path, 'r') as f:
            lines = f.readlines()
        
        assert len(lines) == 3  # Header + 2 data rows
        assert "IP Address" in lines[0]
        assert "192.168.1.1" in lines[1]
        assert "192.168.1.1" in lines[2]
    
    def test_export_empty_results_to_csv(self, tmp_path):
        """Test exporting host with no ports to CSV."""
        host = HostResult(ip="192.168.1.1", reachable=False, ports=[])
        
        output_path = tmp_path / "empty_test.csv"
        export_to_csv([host], str(output_path))
        
        assert output_path.exists()
        
        with open(output_path, 'r') as f:
            lines = f.readlines()
        
        assert len(lines) == 2  # Header + 1 data row


class TestHTMLReportGeneration:
    """Test cases for HTML report generation."""
    
    def test_generate_html_report(self, tmp_path):
        """Test generating HTML report."""
        port = PortResult(port=80, status="open", service="http", banner="nginx/1.18.0")
        
        host = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[port],
            scan_time=datetime.now(),
            scan_duration=3.5
        )
        
        output_path = tmp_path / "test_report.html"
        generate_html_report([host], str(output_path))
        
        assert output_path.exists()
        
        # Verify HTML content
        with open(output_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        assert "<!DOCTYPE html>" in html_content
        assert "SentinelScapyScan Report" in html_content
        assert "192.168.1.1" in html_content
        assert "nginx/1.18.0" in html_content
    
    def test_html_report_with_multiple_hosts(self, tmp_path):
        """Test HTML report with multiple hosts."""
        host1 = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[PortResult(port=80, status="open", service="http")]
        )
        
        host2 = HostResult(
            ip="192.168.1.2",
            reachable=True,
            ports=[PortResult(port=443, status="open", service="https")]
        )
        
        output_path = tmp_path / "multi_host.html"
        generate_html_report([host1, host2], str(output_path))
        
        assert output_path.exists()
        
        with open(output_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        assert "192.168.1.1" in html_content
        assert "192.168.1.2" in html_content
    
    def test_html_report_styling(self, tmp_path):
        """Test HTML report contains styling."""
        host = HostResult(ip="192.168.1.1", reachable=True)
        
        output_path = tmp_path / "styled_report.html"
        generate_html_report([host], str(output_path))
        
        with open(output_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Check for CSS styling
        assert "<style>" in html_content
        assert "background" in html_content
        assert "color" in html_content
    
    def test_html_report_with_config(self, tmp_path):
        """Test HTML report with configuration."""
        host = HostResult(ip="192.168.1.1", reachable=True)
        
        config = {"scan": {"timeout": 5}}
        
        output_path = tmp_path / "config_report.html"
        generate_html_report([host], str(output_path), config=config)
        
        assert output_path.exists()


class TestHostResultModel:
    """Test cases for HostResult model."""
    
    def test_host_result_to_dict(self):
        """Test converting HostResult to dictionary."""
        port1 = PortResult(port=80, status="open", service="http")
        port2 = PortResult(port=443, status="closed")
        
        host = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[port1, port2],
            scan_time=datetime(2024, 1, 1, 12, 0, 0),
            scan_duration=5.5
        )
        
        result_dict = host.to_dict()
        
        assert result_dict["ip"] == "192.168.1.1"
        assert result_dict["reachable"] is True
        assert result_dict["total_ports_scanned"] == 2
        assert result_dict["open_ports"] == 1
        assert result_dict["closed_ports"] == 1
        assert result_dict["scan_duration"] == 5.5
    
    def test_get_open_ports(self):
        """Test getting only open ports."""
        port1 = PortResult(port=80, status="open")
        port2 = PortResult(port=81, status="closed")
        port3 = PortResult(port=443, status="open")
        
        host = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[port1, port2, port3]
        )
        
        open_ports = host.get_open_ports()
        
        assert len(open_ports) == 2
        assert all(p.status == "open" for p in open_ports)
    
    def test_get_services(self):
        """Test getting list of services."""
        port1 = PortResult(port=80, status="open", service="http")
        port2 = PortResult(port=443, status="open", service="https")
        port3 = PortResult(port=8080, status="open")  # No service
        
        host = HostResult(
            ip="192.168.1.1",
            reachable=True,
            ports=[port1, port2, port3]
        )
        
        services = host.get_services()
        
        assert len(services) == 2
        assert "http" in services
        assert "https" in services
