---
description: Implement the entire SentinelScapyScan project according to the specifications below.
auto_execution_mode: 3
---

SentinelScapyScan — Full Implementation Plan
Project Goal
Implement a complete, production-ready, modular cybersecurity automation suite using Scapy, Typer, Rich, asyncio, and Jinja2.
The tool performs network host discovery, port scanning, UDP probing, service fingerprinting, and generates JSON/HTML reports.
Implement the entire project according to the specifications below.
________________________________________
SECTION 1 — Rules
1.	Follow directory structure exactly.
2.	Implement all modules fully — no stubs or placeholders.
3.	Use production-quality Python: typing, docstrings, error handling, async features.
4.	Use Poetry for packaging and dependency management.
5.	Ensure all imports are correct (SentinelScapyScan.*).
6.	Include complete documentation and examples.
7.	Include tests for scanning, fingerprinting, reporting.
8.	All code must be runnable on WSL2/Linux.
9.	Include full CI/CD and pre-commit config.
10.	HTML reports must be visually styled and clean.
________________________________________
SECTION 2 — Directory Structure
Create the folder structure exactly as follows:
SentinelScapyScan/
│
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── .pre-commit-config.yaml
│
├── SentinelScapyScan/
│   ├── __init__.py
│   ├── cli.py
│   ├── manager.py
│   ├── models.py
│
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── arp_scan.py
│   │   ├── icmp_scan.py
│   │   ├── syn_scan.py
│   │   ├── udp_scan.py
│
│   ├── fingerprinting/
│   │   ├── __init__.py
│   │   ├── banner.py
│   │   ├── http_fp.py
│   │   ├── tls_fp.py
│
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── json_writer.py
│   │   ├── html_report.py
│   │   └── templates/
│   │       └── report.html.j2
│
│   └── utils/
│       ├── __init__.py
│       ├── config.py
│       ├── logging.py
│
└── tests/
    ├── test_syn_scan.py
    ├── test_dns_probe.py
    ├── test_report_generation.py
________________________________________
SECTION 3 — Dependencies (Poetry)
Configure pyproject.toml with:
Dependencies
•	scapy
•	typer
•	rich
•	httpx
•	jinja2
•	cryptography
Dev Dependencies
•	black
•	ruff
•	pytest
•	pre-commit
Set project entrypoint to:
[tool.poetry.scripts]
sentinelscapyscan = "SentinelScapyScan.cli:app"
________________________________________
SECTION 4 — Implement Modules
4.1 models.py
Implement:
PortResult
•	port: int
•	status: str (“open”, “closed”, “filtered”)
•	service: Optional[str]
•	banner: Optional[str]
•	http_headers: Optional[dict]
•	tls_info: Optional[dict]
HostResult
•	ip: str
•	reachable: bool
•	ports: list of PortResult
•	Add .to_dict() for JSON serialization.
________________________________________
4.2 scanners
arp_scan.py
•	Scapy ARP + Ether broadcast
•	Return list of active IPv4 hosts
icmp_scan.py
•	ICMP echo-request probe
•	Determine host reachability
syn_scan.py
•	Use sr() and TCP flag 'S'
•	Detect open/closed/filtered
•	Return list of PortResult
udp_scan.py
Implement probes:
•	DNS
•	NTP
•	Generic UDP probe
Return PortResult list with service hints.
________________________________________
4.3 fingerprinting
banner.py
•	Use socket.create_connection
•	Graceful timeout/errors
http_fp.py
•	Use httpx to GET
•	Extract:
o	server
o	CSP
o	CORS
o	cookies
•	Return dict
tls_fp.py
•	Use ssl to:
o	extract certificate
o	issuer
o	subject
o	validity window
o	TLS version
________________________________________
4.4 Scan Manager
File: manager.py
Implement:
1.	Reachability check (ICMP or ARP).
2.	SYN scan for ports.
3.	Launch async fingerprint tasks:
o	banner
o	HTTP headers
o	TLS info
4.	Merge results into HostResult.
5.	Return final host object.
6.	Log status using Rich logger.
________________________________________
SECTION 5 — Reporting
json_writer.py
•	Convert HostResult to JSON
•	Include:
o	timestamp
o	scan duration
o	configuration used
html_report.py
•	Use Jinja2
•	Load template report.html.j2
•	Render:
o	host
o	port table
o	banners
o	HTTP headers
o	TLS info
•	Include CSS styling
report.html.j2
Make a full HTML report with:
•	Header section
•	Summary panel
•	Ports table
•	Color-coded statuses
•	Optional Chart.js support
________________________________________
SECTION 6 — CLI
cli.py
Using Typer + Rich:
Commands:
•	scan
•	report
•	fingerprint
Options:
--target
--ports
--output
--timeout
--udp / --no-udp
--fingerprint / --no-fingerprint
Features:
•	Rich progress bars
•	Spinners
•	Styled output
________________________________________
SECTION 7 — Utilities
config.py
•	Load YAML or TOML
•	Provide defaults:
o	ports list
o	timeouts
o	retry counts
o	concurrency
logging.py
•	RichHandler (color console)
•	RotatingFileHandler → logs/SentinelScapyScan.log
________________________________________
SECTION 8 — Tests
test_syn_scan.py
Use mocks to simulate Scapy sr() responses.
test_dns_probe.py
Mock UDP responses.
test_report_generation.py
•	Create mock HostResult
•	Ensure JSON and HTML files generate successfully
All tests must use pytest.
________________________________________
SECTION 9 — CI/CD
Create .github/workflows/ci.yml:
Jobs:
•	Setup Python / Poetry
•	Install dependencies
•	Run ruff
•	Run black
•	Run tests
•	Build package
________________________________________
SECTION 10 — Pre-Commit Hooks
.pre-commit-config.yaml must include:
•	black
•	ruff
•	trailing whitespace cleanup
•	end-of-file fixer
________________________________________
SECTION 11 — Documentation
README.md
Include:
•	Project overview
•	Features
•	Architecture diagram
•	Installation instructions
•	Usage examples
•	Screenshots of HTML report
•	Future roadmap
docs/architecture.md
Explain modules and workflows.
________________________________________
SECTION 12 — Enhancements 
1.	Chart.js graphs in HTML report
2.	Web dashboard using FastAPI
3.	CVE suggestion engine
4.	Plugin architecture
________________________________________
SECTION 13 — Final Validation
Windsurf must:
1.	Run tests
2.	Validate imports
3.	Validate CLI commands
4.	Generate sample JSON + HTML reports
5.	Confirm project passes:
o	black
o	ruff
o	pytest