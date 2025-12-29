# Contributing to SentinelScapyScan

Thank you for your interest in contributing to SentinelScapyScan! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected behavior**
- **Actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Relevant logs or screenshots**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case and motivation**
- **Proposed solution**
- **Alternative solutions considered**

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make your changes**
   - Follow the coding standards
   - Add tests for new functionality
   - Update documentation as needed

4. **Run tests and linting**
   ```bash
   poetry run pytest
   poetry run black SentinelScapyScan tests
   poetry run ruff check SentinelScapyScan tests
   ```

5. **Commit your changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```
   - Use clear, descriptive commit messages
   - Reference issues in commits (e.g., "Fixes #123")

6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```

7. **Open a Pull Request**
   - Provide a clear description of changes
   - Link related issues
   - Ensure CI passes

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Poetry
- Git

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/SentinelScapyScan.git
cd SentinelScapyScan

# Install dependencies
poetry install

# Activate virtual environment
poetry shell

# Install pre-commit hooks
pre-commit install
```

## Coding Standards

### Python Style

- Follow PEP 8
- Use Black for formatting (line length: 100)
- Use Ruff for linting
- Use type hints where appropriate
- Write docstrings for all public functions/classes

### Code Organization

- Keep functions focused and small
- Use meaningful variable and function names
- Add comments for complex logic
- Organize imports: stdlib, third-party, local

### Testing

- Write tests for all new features
- Maintain or improve code coverage
- Use pytest fixtures for common setup
- Mock external dependencies

### Documentation

- Update README.md for user-facing changes
- Update architecture.md for structural changes
- Add docstrings with examples
- Update CHANGELOG.md

## Project Structure

```
SentinelScapyScan/
├── SentinelScapyScan/     # Main package
│   ├── scanners/          # Scanning modules
│   ├── fingerprinting/    # Fingerprinting modules
│   ├── reporting/         # Reporting modules
│   └── utils/             # Utility modules
├── tests/                 # Test suite
├── docs/                  # Documentation
└── .github/               # GitHub workflows
```

## Testing Guidelines

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=SentinelScapyScan

# Run specific test file
poetry run pytest tests/test_syn_scan.py

# Run with verbose output
poetry run pytest -v
```

### Writing Tests

- Use descriptive test names
- Test both success and failure cases
- Use mocks for external dependencies
- Keep tests independent

Example:
```python
def test_syn_scan_open_port(self, mock_sr):
    """Test SYN scan detecting an open port."""
    # Setup
    sent_packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="S")
    recv_packet = IP(src="192.168.1.1") / TCP(sport=80, flags="SA")
    mock_sr.return_value = ([(sent_packet, recv_packet)], [])
    
    # Execute
    results = syn_scan("192.168.1.1", [80])
    
    # Assert
    assert len(results) == 1
    assert results[0].status == "open"
```

## Code Review Process

### For Contributors

- Respond to feedback promptly
- Be open to suggestions
- Update PR based on reviews
- Keep PR focused on single feature/fix

### For Reviewers

- Be constructive and respectful
- Explain reasoning for suggestions
- Approve when ready
- Test changes locally if needed

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release tag
4. Build and publish to PyPI
5. Create GitHub release

## Questions?

- Open a discussion on GitHub
- Check existing documentation
- Review closed issues for similar questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to SentinelScapyScan! 🎉
