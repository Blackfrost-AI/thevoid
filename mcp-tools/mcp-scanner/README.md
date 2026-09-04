# MCP-Scanner

A comprehensive vulnerability scanner for MCP (Model Context Protocol) server deployments.

## Overview

MCP-Scanner provides pattern-based vulnerability detection, CVE matching, dependency analysis, and configuration drift detection for MCP servers.

## Features

- **Pattern-Based Analysis**: Detects known vulnerability patterns in MCP server configurations
- **CVE Matching**: Correlates detected vulnerabilities with known CVE entries
- **Dependency Inspection**: Analyzes project dependencies for vulnerabilities
- **Configuration Drift**: Detects deviations from baseline configurations
- **Multi-Format Reporting**: Generates reports in HTML, PDF, and JSON formats
- **Docker Support**: Containerized deployment with Docker

## Installation

### Prerequisites

- Python 3.11 or higher
- pip 23.0 or higher
- Docker 24.0 or higher (optional)

### Install from Source

```bash
git clone https://github.com/mcp-tools/mcp-scanner.git
cd mcp-scanner
pip install -r requirements.txt
```

### Docker Installation

```bash
docker build -t mcp-scanner:1.0.0 .
docker run -p 8080:8080 mcp-scanner:1.0.0
```

## Usage

### Basic Scanning

```python
from mcp_scanner import Scanner

scanner = Scanner()
result = scanner.scan(target_path="/path/to/mcp/server")
print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
```

### Report Generation

```python
report_path = scanner.generate_report(
    result=result,
    format="html",
    output_path="reports/scan_report.html"
)
```

### Configuration

Create a configuration file at `config/scanner.yaml`:

```yaml
scanner:
  scan_depth: comprehensive
  include_dependencies: true
  drift_detection: true
  report_formats:
    - html
    - json
    - pdf
```

## Project Structure

```
mcp-scanner/
├── src/
│   ├── __init__.py
│   ├── scanner.py
│   ├── analyzer.py
│   ├── cve_matcher.py
│   ├── dependency_inspector.py
│   ├── config_parser.py
│   └── report_generator.py
├── config/
│   └── scanner.yaml
├── tests/
│   └── test_scanner.py
├── scripts/
│   └── entrypoint.sh
├── Dockerfile
├── requirements.txt
└── README.md
```

## API Reference

### Scanner Class

**Methods:**
- `scan(target_path, options)`: Perform comprehensive scan
- `generate_report(result, format, output_path)`: Generate scan report
- `get_results()`: Retrieve all scan results

### ScanResult Class

**Attributes:**
- `target_path`: Scanned target path
- `vulnerabilities`: List of detected vulnerabilities
- `dependencies`: Analyzed dependencies
- `configuration_drift`: Configuration drift findings
- `metadata`: Scan metadata and statistics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## License

MIT License - See LICENSE file for details.

## Support

For issues and feature requests, please visit the GitHub repository.
