# SentinelScapyScan Architecture

## Overview

SentinelScapyScan is designed as a modular, extensible network security scanning framework. The architecture follows clean separation of concerns with distinct layers for scanning, fingerprinting, reporting, and orchestration.

## Core Components

### 1. Data Models (`models.py`)

The foundation of the system, defining core data structures:

- **PortResult**: Represents scan results for a single port
  - Port number
  - Status (open/closed/filtered)
  - Service identification
  - Banner information
  - HTTP headers (if applicable)
  - TLS information (if applicable)

- **HostResult**: Aggregates results for an entire host
  - IP address
  - Reachability status
  - List of port results
  - Scan metadata (timestamp, duration)
  - Helper methods for filtering and analysis

### 2. Scanners Module

Located in `scanners/`, this module contains specialized scanning implementations:

#### ARP Scanner (`arp_scan.py`)
- **Purpose**: Local network host discovery
- **Method**: Broadcasts ARP requests to discover active hosts
- **Use Case**: Identifying all devices on a local network segment
- **Requirements**: Raw socket access (root/admin privileges)

#### ICMP Scanner (`icmp_scan.py`)
- **Purpose**: Host reachability detection
- **Method**: Sends ICMP echo requests (ping)
- **Use Case**: Determining if hosts are online before port scanning
- **Features**: Configurable retry count and timeout

#### SYN Scanner (`syn_scan.py`)
- **Purpose**: TCP port scanning
- **Method**: Half-open SYN scan (stealth scanning)
- **Advantages**:
  - Faster than full TCP connect
  - Less likely to be logged
  - Identifies open, closed, and filtered ports
- **Process**:
  1. Send SYN packet
  2. Analyze response:
     - SYN-ACK → Port is open
     - RST → Port is closed
     - No response/ICMP → Port is filtered
  3. Send RST to close connection

#### UDP Scanner (`udp_scan.py`)
- **Purpose**: UDP port scanning and service detection
- **Method**: Service-specific probes
- **Supported Services**:
  - DNS (port 53)
  - NTP (port 123)
  - SNMP (port 161)
  - Generic UDP probing
- **Challenges**: UDP is stateless, making detection harder
- **Response Analysis**:
  - UDP response → Port is open
  - ICMP unreachable → Port is closed
  - No response → Port is open|filtered

### 3. Fingerprinting Module

Located in `fingerprinting/`, provides service identification:

#### Banner Grabber (`banner.py`)
- **Purpose**: Identify services by their banners
- **Method**: 
  1. Establish TCP connection
  2. Send service-specific probe (if applicable)
  3. Read response banner
- **Service Detection**: Pattern matching on banner text
- **Examples**:
  - SSH: "SSH-2.0-OpenSSH_8.2"
  - HTTP: "HTTP/1.1 200 OK"
  - FTP: "220 FTP Server Ready"

#### HTTP Fingerprinter (`http_fp.py`)
- **Purpose**: Extract HTTP/HTTPS service information
- **Features**:
  - Server identification
  - Security header analysis (CSP, CORS, HSTS)
  - Technology detection (frameworks, CMS)
  - Cookie analysis
- **Async Support**: Uses httpx for efficient concurrent requests

#### TLS Fingerprinter (`tls_fp.py`)
- **Purpose**: Analyze TLS/SSL configurations
- **Information Extracted**:
  - TLS version
  - Cipher suite
  - Certificate details (subject, issuer, validity)
  - Subject Alternative Names (SANs)
  - Certificate expiration
- **Security Analysis**: Identifies weak configurations

### 4. Scan Manager (`manager.py`)

The orchestration layer that coordinates all scanning activities:

**Workflow**:
1. **Reachability Check**: ICMP ping (optional)
2. **Port Scanning**: TCP SYN scan
3. **UDP Scanning**: If enabled
4. **Fingerprinting**: Parallel service identification
5. **Result Aggregation**: Combine all data into HostResult

**Features**:
- Synchronous and asynchronous modes
- Configurable concurrency limits
- Error handling and logging
- Progress tracking

**Async Architecture**:
```python
async def scan_host_async():
    # Reachability check
    reachable = await asyncio.to_thread(icmp_scan, target)
    
    # Port scanning
    tcp_results = await asyncio.to_thread(syn_scan, target, ports)
    
    # Concurrent fingerprinting
    tasks = [fingerprint_port_async(port) for port in open_ports]
    await asyncio.gather(*tasks)
```

### 5. Reporting Module

Located in `reporting/`, handles output generation:

#### JSON Writer (`json_writer.py`)
- **Purpose**: Machine-readable output
- **Features**:
  - Complete scan data serialization
  - Metadata and statistics
  - Configuration snapshot
  - CSV export capability
- **Use Cases**: Automation, integration, data analysis

#### HTML Reporter (`html_report.py`)
- **Purpose**: Human-readable reports
- **Technology**: Jinja2 templating
- **Features**:
  - Modern, responsive design
  - Color-coded status indicators
  - Interactive tables
  - Summary statistics
  - Chart.js support (optional)

#### Template System (`templates/report.html.j2`)
- **Design**: Modern gradient UI
- **Sections**:
  - Header with scan metadata
  - Statistics dashboard
  - Host cards with port tables
  - Service summary
  - Footer with generation info

### 6. Utilities Module

Located in `utils/`, provides supporting functionality:

#### Configuration (`config.py`)
- **Purpose**: Centralized configuration management
- **Formats**: YAML and TOML support
- **Features**:
  - Default configuration
  - Configuration merging
  - Port list parsing
  - Validation
- **Port Specifications**:
  - Named lists: "common", "all", "default"
  - Ranges: "8000-8100"
  - Individual: "80,443,8080"

#### Logging (`logging.py`)
- **Purpose**: Comprehensive logging system
- **Features**:
  - Rich console output with colors
  - File rotation
  - Configurable log levels
  - Context managers for progress tracking
- **Handlers**:
  - RichHandler: Console output with formatting
  - RotatingFileHandler: File logging with rotation

### 7. CLI Interface (`cli.py`)

Built with Typer and Rich for excellent UX:

**Commands**:
- `scan`: Main scanning command
- `report`: Generate HTML from JSON
- `fingerprint`: Standalone fingerprinting
- `version`: Show version info

**Features**:
- Progress bars and spinners
- Color-coded output
- Formatted tables
- Error handling with helpful messages
- Comprehensive help text

## Data Flow

```
User Input (CLI)
    ↓
Configuration Loading
    ↓
Scan Manager Initialization
    ↓
┌─────────────────────────────────┐
│   Reachability Check (ICMP)     │
└─────────────────────────────────┘
    ↓
┌─────────────────────────────────┐
│   Port Scanning (SYN/UDP)       │
└─────────────────────────────────┘
    ↓
┌─────────────────────────────────┐
│   Service Fingerprinting        │
│   ├─ Banner Grabbing            │
│   ├─ HTTP Fingerprinting        │
│   └─ TLS Inspection             │
└─────────────────────────────────┘
    ↓
┌─────────────────────────────────┐
│   Result Aggregation            │
└─────────────────────────────────┘
    ↓
┌─────────────────────────────────┐
│   Report Generation             │
│   ├─ JSON                       │
│   ├─ HTML                       │
│   └─ CSV                        │
└─────────────────────────────────┘
    ↓
Output to User
```

## Design Principles

### 1. Modularity
- Each scanner is independent
- Easy to add new scanning techniques
- Pluggable fingerprinting methods

### 2. Extensibility
- Clear interfaces for new modules
- Configuration-driven behavior
- Plugin architecture ready

### 3. Performance
- Asynchronous operations where beneficial
- Concurrent fingerprinting
- Efficient packet handling with Scapy

### 4. Reliability
- Comprehensive error handling
- Graceful degradation
- Detailed logging

### 5. Usability
- Rich CLI with progress indicators
- Beautiful reports
- Sensible defaults

## Security Considerations

### Privilege Requirements
- Raw socket operations require root/admin
- Scapy needs elevated privileges for:
  - ARP scanning
  - SYN scanning
  - ICMP scanning
  - UDP scanning

### Ethical Use
- Tool designed for authorized testing only
- No built-in evasion techniques
- Logging for accountability

### Data Handling
- Sensitive data (certificates, headers) stored securely
- Reports may contain sensitive information
- No data transmitted externally

## Performance Characteristics

### Scanning Speed
- **SYN Scan**: ~1000 ports/second (typical)
- **UDP Scan**: Slower due to protocol nature
- **Fingerprinting**: Depends on service response time

### Resource Usage
- **Memory**: Minimal, scales with result size
- **CPU**: Low to moderate
- **Network**: Depends on scan scope

### Optimization Strategies
- Concurrent operations
- Configurable timeouts
- Batch processing
- Result streaming (future enhancement)

## Future Enhancements

### Planned Features
1. **Web Dashboard**: FastAPI-based real-time monitoring
2. **CVE Integration**: Automatic vulnerability suggestions
3. **Plugin System**: Custom scanner plugins
4. **Distributed Scanning**: Multi-node coordination
5. **Advanced Evasion**: Timing, fragmentation options
6. **Network Mapping**: Topology visualization
7. **Database Backend**: Persistent scan history
8. **API Server**: RESTful API for integration

### Scalability Improvements
- Database storage for large scans
- Distributed worker architecture
- Result streaming
- Incremental reporting

## Testing Strategy

### Unit Tests
- Mock Scapy responses
- Test individual scanners
- Validate data models
- Report generation

### Integration Tests
- End-to-end scanning workflows
- Configuration loading
- Report generation pipeline

### Performance Tests
- Large-scale scans
- Concurrent operations
- Memory profiling

## Deployment

### Recommended Environment
- Linux/WSL2 for best compatibility
- Python 3.8+ with Poetry
- Root/admin access for scanning
- Sufficient disk space for logs/reports

### Production Considerations
- Log rotation configuration
- Report storage management
- Access control for sensitive scans
- Network bandwidth considerations

## Conclusion

SentinelScapyScan's architecture prioritizes modularity, performance, and usability. The clean separation of concerns allows for easy maintenance and extension while providing a robust foundation for network security scanning operations.
