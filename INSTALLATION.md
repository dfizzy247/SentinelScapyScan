# Installation Guide

Complete installation instructions for SentinelScapyScan.

## System Requirements

- **Operating System**: Linux, macOS, or Windows (with WSL2)
- **Python**: 3.8 or higher
- **Privileges**: Root/Administrator access for scanning operations
- **Memory**: Minimum 512MB RAM
- **Disk Space**: ~100MB for installation

## Installation Methods

### Method 1: Using Poetry (Recommended)

Poetry provides dependency management and virtual environment handling.

#### Step 1: Install Poetry

**Linux/macOS/WSL2:**
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

**Windows (PowerShell):**
```powershell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

Add Poetry to your PATH:
```bash
# Linux/macOS
export PATH="$HOME/.local/bin:$PATH"

# Windows
# Add %APPDATA%\Python\Scripts to your PATH
```

#### Step 2: Clone Repository

```bash
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan
```

#### Step 3: Install Dependencies

```bash
# Install all dependencies
poetry install

# Install only production dependencies (no dev tools)
poetry install --no-dev
```

#### Step 4: Activate Virtual Environment

```bash
poetry shell
```

#### Step 5: Verify Installation

```bash
sentinelscapyscan version
```

### Method 2: Using pip

#### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan
```

#### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

#### Step 3: Install Package

```bash
# Install in development mode
pip install -e .

# Or install from requirements
pip install scapy typer rich httpx jinja2 cryptography pyyaml toml
```

#### Step 4: Verify Installation

```bash
sentinelscapyscan version
```

### Method 3: From PyPI (Future)

Once published to PyPI:

```bash
pip install sentinelscapyscan
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-venv

# Install system dependencies for Scapy
sudo apt install tcpdump libpcap-dev

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Clone and install
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan
poetry install
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Clone and install
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan
poetry install
```

### Windows with WSL2 (Recommended)

```bash
# Install WSL2 (PowerShell as Administrator)
wsl --install

# Restart computer

# Inside WSL2, follow Linux instructions
sudo apt update
sudo apt install python3 python3-pip python3-venv tcpdump libpcap-dev
curl -sSL https://install.python-poetry.org | python3 -
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan
poetry install
```

### Windows Native (Limited Support)

**Note**: Native Windows support is limited. WSL2 is strongly recommended.

```powershell
# Install Python from python.org

# Install Npcap (WinPcap replacement)
# Download from: https://npcap.com/

# Install Poetry
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -

# Clone and install
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan
poetry install
```

## Development Installation

For contributors and developers:

```bash
# Clone repository
git clone https://github.com/yourusername/SentinelScapyScan.git
cd SentinelScapyScan

# Install with dev dependencies
poetry install

# Install pre-commit hooks
poetry run pre-commit install

# Run tests
poetry run pytest

# Run linting
poetry run ruff check SentinelScapyScan tests
poetry run black --check SentinelScapyScan tests
```

## Dependency Installation Issues

### Scapy Installation Fails

**Issue**: Scapy requires libpcap

**Solution**:
```bash
# Linux
sudo apt install libpcap-dev tcpdump

# macOS
brew install libpcap

# Windows
# Install Npcap from https://npcap.com/
```

### Cryptography Build Errors

**Issue**: Missing build tools

**Solution**:
```bash
# Linux
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# macOS
xcode-select --install
```

### Permission Errors

**Issue**: Cannot install to system Python

**Solution**: Always use virtual environments
```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e .
```

## Verification

After installation, verify everything works:

```bash
# Check version
sentinelscapyscan version

# Run validation script
python setup_and_validate.py

# Run tests
poetry run pytest

# Check CLI help
sentinelscapyscan --help
```

## Post-Installation Setup

### 1. Create Configuration File

```bash
cp config.example.yaml config.yaml
nano config.yaml  # Edit as needed
```

### 2. Create Output Directories

```bash
mkdir -p logs reports
```

### 3. Set Permissions (Linux/macOS)

For non-root scanning (limited functionality):
```bash
# Allow Python to use raw sockets
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

**Warning**: This reduces security. Only do this on trusted systems.

### 4. Test Installation

```bash
# Test without root (limited)
sentinelscapyscan fingerprint example.com 80 --http

# Test with root (full functionality)
sudo sentinelscapyscan scan 127.0.0.1 -p 80,443
```

## Updating

### Update with Poetry

```bash
cd SentinelScapyScan
git pull
poetry install
```

### Update with pip

```bash
cd SentinelScapyScan
git pull
pip install -e . --upgrade
```

## Uninstallation

### Remove with Poetry

```bash
# Deactivate virtual environment
exit

# Remove project directory
rm -rf SentinelScapyScan
```

### Remove with pip

```bash
# Uninstall package
pip uninstall sentinelscapyscan

# Remove project directory
rm -rf SentinelScapyScan
```

## Troubleshooting

### "Command not found: sentinelscapyscan"

**Solution**: Ensure virtual environment is activated
```bash
poetry shell
# or
source venv/bin/activate
```

### "Permission denied" when scanning

**Solution**: Run with sudo/administrator privileges
```bash
sudo sentinelscapyscan scan 192.168.1.1
```

### Import errors after installation

**Solution**: Reinstall dependencies
```bash
poetry install --no-cache
# or
pip install -e . --force-reinstall
```

### Tests failing

**Solution**: Install dev dependencies
```bash
poetry install  # Includes dev dependencies
```

## Getting Help

- 📖 [Quick Start Guide](QUICKSTART.md)
- 📚 [Full Documentation](README.md)
- 🐛 [Issue Tracker](https://github.com/yourusername/SentinelScapyScan/issues)
- 💬 [Discussions](https://github.com/yourusername/SentinelScapyScan/discussions)

## Next Steps

After successful installation:

1. Read the [Quick Start Guide](QUICKSTART.md)
2. Review [Configuration Options](config.example.yaml)
3. Try example scans from [README.md](README.md)
4. Explore the [Architecture](docs/architecture.md)

---

Happy Scanning! 🛡️
