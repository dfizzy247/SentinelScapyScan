#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Setup and validation script for SentinelScapyScan.

This script validates the project structure, imports, and generates sample reports.
"""

import sys
import io
from pathlib import Path
from datetime import datetime

# Set UTF-8 encoding for Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


def validate_project_structure():
    """Validate that all required files and directories exist."""
    print("🔍 Validating project structure...")
    
    required_files = [
        "pyproject.toml",
        "README.md",
        "LICENSE",
        ".gitignore",
        ".pre-commit-config.yaml",
        "SentinelScapyScan/__init__.py",
        "SentinelScapyScan/cli.py",
        "SentinelScapyScan/manager.py",
        "SentinelScapyScan/models.py",
        "SentinelScapyScan/scanners/__init__.py",
        "SentinelScapyScan/scanners/arp_scan.py",
        "SentinelScapyScan/scanners/icmp_scan.py",
        "SentinelScapyScan/scanners/syn_scan.py",
        "SentinelScapyScan/scanners/udp_scan.py",
        "SentinelScapyScan/fingerprinting/__init__.py",
        "SentinelScapyScan/fingerprinting/banner.py",
        "SentinelScapyScan/fingerprinting/http_fp.py",
        "SentinelScapyScan/fingerprinting/tls_fp.py",
        "SentinelScapyScan/reporting/__init__.py",
        "SentinelScapyScan/reporting/json_writer.py",
        "SentinelScapyScan/reporting/html_report.py",
        "SentinelScapyScan/reporting/templates/report.html.j2",
        "SentinelScapyScan/utils/__init__.py",
        "SentinelScapyScan/utils/config.py",
        "SentinelScapyScan/utils/logging.py",
        "tests/__init__.py",
        "tests/test_syn_scan.py",
        "tests/test_dns_probe.py",
        "tests/test_report_generation.py",
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print(f"  ❌ Missing: {file_path}")
        else:
            print(f"  ✓ Found: {file_path}")
    
    if missing_files:
        print(f"\n❌ Missing {len(missing_files)} required files!")
        return False
    else:
        print("\n✅ All required files present!")
        return True


def validate_imports():
    """Validate that all modules can be imported."""
    print("\n🔍 Validating imports...")
    
    modules_to_test = [
        "SentinelScapyScan",
        "SentinelScapyScan.models",
        "SentinelScapyScan.scanners.arp_scan",
        "SentinelScapyScan.scanners.icmp_scan",
        "SentinelScapyScan.scanners.syn_scan",
        "SentinelScapyScan.scanners.udp_scan",
        "SentinelScapyScan.fingerprinting.banner",
        "SentinelScapyScan.fingerprinting.http_fp",
        "SentinelScapyScan.fingerprinting.tls_fp",
        "SentinelScapyScan.reporting.json_writer",
        "SentinelScapyScan.reporting.html_report",
        "SentinelScapyScan.utils.config",
        "SentinelScapyScan.utils.logging",
        "SentinelScapyScan.manager",
        "SentinelScapyScan.cli",
    ]
    
    failed_imports = []
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"  ✓ {module}")
        except ImportError as e:
            print(f"  ❌ {module}: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n❌ Failed to import {len(failed_imports)} modules!")
        return False
    else:
        print("\n✅ All modules imported successfully!")
        return True


def generate_sample_reports():
    """Generate sample JSON and HTML reports."""
    print("\n📊 Generating sample reports...")
    
    try:
        from SentinelScapyScan.models import HostResult, PortResult
        from SentinelScapyScan.reporting.json_writer import write_json_report
        from SentinelScapyScan.reporting.html_report import generate_html_report
        
        # Create sample data
        ports = [
            PortResult(
                port=22,
                status="open",
                service="ssh",
                banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            ),
            PortResult(
                port=80,
                status="open",
                service="http",
                banner="Apache/2.4.41 (Ubuntu)"
            ),
            PortResult(
                port=443,
                status="open",
                service="https",
                http_headers={
                    "server": "nginx/1.18.0",
                    "status_code": 200
                },
                tls_info={
                    "tls_version": "TLSv1.3",
                    "cipher_suite": {
                        "name": "TLS_AES_256_GCM_SHA384",
                        "bits": 256
                    }
                }
            ),
            PortResult(port=8080, status="closed"),
            PortResult(port=3306, status="filtered"),
        ]
        
        host = HostResult(
            ip="192.168.1.100",
            reachable=True,
            ports=ports,
            scan_time=datetime.now(),
            scan_duration=12.5
        )
        
        # Create output directory
        output_dir = Path("sample_reports")
        output_dir.mkdir(exist_ok=True)
        
        # Generate JSON report
        json_path = output_dir / "sample_scan.json"
        write_json_report([host], str(json_path))
        print(f"  ✓ JSON report: {json_path}")
        
        # Generate HTML report
        html_path = output_dir / "sample_scan.html"
        generate_html_report([host], str(html_path))
        print(f"  ✓ HTML report: {html_path}")
        
        print("\n✅ Sample reports generated successfully!")
        print(f"\n📁 Reports saved to: {output_dir.absolute()}")
        return True
        
    except Exception as e:
        print(f"\n❌ Failed to generate reports: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_dependencies():
    """Check if all required dependencies are installed."""
    print("\n🔍 Checking dependencies...")
    
    required_packages = [
        "scapy",
        "typer",
        "rich",
        "httpx",
        "jinja2",
        "cryptography",
        "yaml",
        "toml",
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            if package == "yaml":
                __import__("yaml")
            else:
                __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n❌ Missing {len(missing_packages)} packages!")
        print("\nInstall missing packages with:")
        print("  poetry install")
        return False
    else:
        print("\n✅ All dependencies installed!")
        return True


def main():
    """Run all validation checks."""
    print("=" * 60)
    print("SentinelScapyScan - Setup & Validation")
    print("=" * 60)
    
    results = []
    
    # Run validation checks
    results.append(("Project Structure", validate_project_structure()))
    results.append(("Dependencies", check_dependencies()))
    results.append(("Module Imports", validate_imports()))
    results.append(("Sample Reports", generate_sample_reports()))
    
    # Print summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    for check_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{check_name:.<40} {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("=" * 60)
    if all_passed:
        print("\n🎉 All validation checks passed!")
        print("\nNext steps:")
        print("  1. Install dependencies: poetry install")
        print("  2. Run tests: poetry run pytest")
        print("  3. Try the CLI: poetry run sentinelscapyscan --help")
        print("  4. View sample reports in: sample_reports/")
        return 0
    else:
        print("\n⚠️  Some validation checks failed!")
        print("\nPlease fix the issues above before proceeding.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
