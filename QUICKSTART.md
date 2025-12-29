# 🚀 Quick Start Guide

Get started with SentinelScapyScan in 5 minutes!

## Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (for raw packet operations)
- WSL2/Linux (recommended for Windows users)

## Installation

### Step 1: Install Poetry

```bash
# Linux/WSL2/macOS
curl -sSL https://install.python-poetry.org | python3 -

# Windows (PowerShell)
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

### Step 2: Clone and Install

```bash
# Clone the repository
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan

# Install dependencies
poetry install

# Activate virtual environment
poetry shell
```

### Step 3: Verify Installation

```bash
sentinelscapyscan version
```

## First Scan

### Basic Host Scan

```bash
# Scan a single host (requires sudo/admin)
sudo sentinelscapyscan scan 192.168.1.1
```

### Scan with Output

```bash
# Save results to reports
sudo sentinelscapyscan scan 192.168.1.1 -o reports/my_first_scan
```

This will generate:
- `reports/my_first_scan.json` - Machine-readable results
- `reports/my_first_scan.html` - Beautiful HTML report

### Custom Port Scan

```bash
# Scan specific ports
sudo sentinelscapyscan scan 192.168.1.1 -p 80,443,8080

# Scan port range
sudo sentinelscapyscan scan 192.168.1.1 -p 8000-9000

# Scan common ports (1-1024)
sudo sentinelscapyscan scan 192.168.1.1 -p common
```

## Common Use Cases

### Web Server Scan

```bash
# Scan web server with fingerprinting
sudo sentinelscapyscan scan example.com -p 80,443 -o web_scan
```

### Network Discovery

```bash
# Scan entire subnet (use with caution!)
sudo sentinelscapyscan scan 192.168.1.0/24 -p 22,80,443
```

### Service Fingerprinting

```bash
# Fingerprint specific service
sentinelscapyscan fingerprint example.com 443 --https --tls

# Get all information
sentinelscapyscan fingerprint example.com 443 --all
```

### Fast Scan (No Fingerprinting)

```bash
# Quick port scan without service detection
sudo sentinelscapyscan scan 192.168.1.1 --no-fingerprint
```

## Configuration

### Create Custom Config

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit with your preferences
nano config.yaml

# Use custom config
sudo sentinelscapyscan scan 192.168.1.1 -c config.yaml
```

### Example Configuration

```yaml
scan:
  timeout: 5
  enable_udp: true
  enable_fingerprinting: true

ports:
  default_tcp_ports:
    - 22
    - 80
    - 443
    - 3306
    - 8080

logging:
  level: "DEBUG"
```

## Viewing Reports

### HTML Report

Open the generated HTML file in your browser:

```bash
# Linux/WSL2
xdg-open reports/my_scan.html

# macOS
open reports/my_scan.html

# Windows
start reports/my_scan.html
```

### JSON Report

Process JSON results with tools:

```bash
# Pretty print
cat reports/my_scan.json | python -m json.tool

# Extract open ports
cat reports/my_scan.json | jq '.results[].ports[] | select(.status=="open")'
```

## Troubleshooting

### Permission Denied

**Problem**: `PermissionError: Operation not permitted`

**Solution**: Run with sudo/administrator privileges
```bash
sudo sentinelscapyscan scan 192.168.1.1
```

### Module Not Found

**Problem**: `ModuleNotFoundError: No module named 'scapy'`

**Solution**: Ensure virtual environment is activated
```bash
poetry shell
```

### Scapy Warnings

**Problem**: Lots of Scapy warnings in output

**Solution**: Use quiet mode
```bash
sudo sentinelscapyscan scan 192.168.1.1 --quiet
```

### Slow Scans

**Problem**: Scans taking too long

**Solution**: Reduce timeout and disable fingerprinting
```bash
sudo sentinelscapyscan scan 192.168.1.1 -t 1 --no-fingerprint
```

## CLI Options Reference

### Global Options

- `-v, --verbose` - Verbose output
- `-d, --debug` - Debug output
- `-q, --quiet` - Suppress output

### Scan Command

```bash
sentinelscapyscan scan TARGET [OPTIONS]
```

**Options:**
- `-p, --ports TEXT` - Ports to scan (default: "default")
- `-o, --output PATH` - Output file path (without extension)
- `-t, --timeout INT` - Timeout in seconds (default: 3)
- `--udp` - Enable UDP scanning
- `--no-fingerprint` - Disable service fingerprinting
- `--skip-ping` - Skip host reachability check
- `--json/--no-json` - Generate JSON report (default: yes)
- `--html/--no-html` - Generate HTML report (default: yes)
- `--csv` - Generate CSV report
- `-c, --config PATH` - Configuration file

### Fingerprint Command

```bash
sentinelscapyscan fingerprint TARGET PORT [OPTIONS]
```

**Options:**
- `--http` - HTTP fingerprinting
- `--https` - HTTPS fingerprinting
- `--tls` - TLS fingerprinting
- `--banner` - Banner grabbing
- `-a, --all` - All fingerprinting methods

### Report Command

```bash
sentinelscapyscan report INPUT_FILE [OPTIONS]
```

**Options:**
- `-o, --output PATH` - Output HTML file path

## Next Steps

1. **Read the full documentation**: Check out [README.md](README.md)
2. **Explore architecture**: See [docs/architecture.md](docs/architecture.md)
3. **Customize configuration**: Edit `config.yaml`
4. **Run tests**: `poetry run pytest`
5. **Contribute**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## Examples

### Example 1: Complete Web Application Scan

```bash
sudo sentinelscapyscan scan webapp.example.com \
  -p 80,443,8080,8443 \
  -o scans/webapp_$(date +%Y%m%d) \
  --timeout 5
```

### Example 2: Database Server Audit

```bash
sudo sentinelscapyscan scan db.example.com \
  -p 3306,5432,27017,6379 \
  -o scans/database_audit \
  --no-fingerprint
```

### Example 3: Network Reconnaissance

```bash
# Discover hosts
sudo sentinelscapyscan scan 192.168.1.0/24 \
  -p 22,80,443 \
  --skip-ping \
  -o scans/network_recon
```

### Example 4: SSL/TLS Audit

```bash
# Check TLS configuration
sentinelscapyscan fingerprint secure.example.com 443 \
  --https --tls > tls_audit.txt
```

## Tips & Best Practices

1. **Always get permission** before scanning networks you don't own
2. **Start with small scans** to test configuration
3. **Use configuration files** for consistent scanning
4. **Save reports** with timestamps for tracking
5. **Review logs** in `logs/sentinelscapyscan.log` for issues
6. **Use --skip-ping** for hosts that block ICMP
7. **Enable UDP scanning** only when needed (slower)
8. **Adjust timeout** based on network conditions

## Getting Help

```bash
# General help
sentinelscapyscan --help

# Command-specific help
sentinelscapyscan scan --help
sentinelscapyscan fingerprint --help
sentinelscapyscan report --help
```

## Resources

- 📖 [Full Documentation](README.md)
- 🏗️ [Architecture Guide](docs/architecture.md)
- 🤝 [Contributing Guide](CONTRIBUTING.md)
- 🐛 [Issue Tracker](https://github.com/yourusername/SentinelScapyScan/issues)

---

Happy Scanning! 🛡️
