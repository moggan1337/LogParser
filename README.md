# LogParser - Advanced Log Parsing and Analysis Engine

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)

**High-performance, extensible log parsing library with support for multiple formats, pattern matching, aggregation, and real-time alerting.**

[Features](#features) • [Architecture](#architecture) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [API Reference](#api-reference) • [Configuration](#configuration) • [Benchmarks](#performance-benchmarks)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Supported Formats](#supported-formats)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Performance Benchmarks](#performance-benchmarks)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

LogParser is a comprehensive Python library designed for parsing, analyzing, and monitoring log files from various sources. It provides a unified interface for handling different log formats with built-in support for pattern matching, statistical analysis, aggregation, and alerting.

### Key Benefits

- **Multi-format Support**: Seamlessly parse JSON, Apache, nginx, and syslog formats
- **High Performance**: Process millions of log entries with optimized parsing algorithms
- **Extensible**: Easy to add custom formatters and patterns
- **Memory Efficient**: Streaming parser for large files without loading into memory
- **Real-time Analysis**: Built-in anomaly detection and alerting capabilities
- **Type-safe**: Full type hints and comprehensive test coverage

---

## Features

### 1. Pattern Matching

LogParser includes a powerful pattern matching system for extracting structured data from unstructured log entries:

```python
from logparser.patterns import PatternMatcher, PatternRegistry, create_common_patterns

# Create matcher with common patterns pre-loaded
registry = PatternRegistry()
create_common_patterns(registry)
matcher = PatternMatcher(registry)

# Match patterns in text
result = matcher.match("2024-01-15T10:30:00Z Server started on port 8080")
print(result.groups)  # {'timestamp': '2024-01-15T10:30:00Z'}
```

**Built-in Patterns:**
| Pattern | Description | Example |
|---------|-------------|---------|
| `timestamp_iso` | ISO 8601 timestamps | `2024-01-15T10:30:00Z` |
| `ip_address` | IPv4 addresses | `192.168.1.100` |
| `email` | Email addresses | `user@example.com` |
| `url` | HTTP URLs | `https://api.example.com` |
| `uuid` | UUID identifiers | `550e8400-e29b-41d4-a716-446655440000` |
| `http_status` | HTTP status codes | `200`, `404`, `500` |
| `error_level` | Log levels | `ERROR`, `WARNING`, `INFO` |
| `http_method` | HTTP methods | `GET`, `POST`, `PUT` |

### 2. Structured Parsing

Extract structured data from log entries with field-level precision:

```python
from logparser import LogParser, LogFormat

parser = LogParser(format=LogFormat.JSON)
entry = parser.parse_line('{"level": "ERROR", "message": "Connection failed", "database": "primary"}')

# Access parsed fields
print(entry.level)      # 'ERROR'
print(entry.message)     # 'Connection failed'
print(entry.metadata)    # {'database': 'primary'}
```

### 3. Aggregation

Aggregate log data by various dimensions:

```python
from logparser import LogAggregator

aggregator = LogAggregator()

# Aggregate by field
result = aggregator.aggregate_by_field(entries, field="level", metric="count")

# Aggregate by time window
result = aggregator.aggregate_by_time(entries, interval="hour")

# Top N analysis
top_sources = aggregator.top_n(entries, field="source", n=10)
```

### 4. Real-time Alerting

Configure alert rules based on log patterns:

```python
from logparser import LogAlerter, AlertSeverity

alerter = LogAlerter()

# Add alert rules
alerter.add_rule(
    name="high_error_rate",
    condition="level == 'ERROR'",
    severity=AlertSeverity.ERROR,
    match_count=3,
    cooldown_seconds=60
)

# Process entries and trigger alerts
events = alerter.process_entries(entries)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LogParser Architecture                          │
└─────────────────────────────────────────────────────────────────────────────┘

                                ┌─────────────────┐
                                │   Input Layer   │
                                │  (Files, URLs,  │
                                │   Streams)      │
                                └────────┬────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Core Components                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │    Parser    │    │   Analyzer   │    │  Aggregator  │    │  Alerter  │ │
│  ├──────────────┤    ├──────────────┤    ├──────────────┤    ├───────────┤ │
│  │              │    │              │    │              │    │           │ │
│  │  - JSON      │    │  - Stats     │    │  - Group By  │    │  - Rules  │ │
│  │  - Apache    │    │  - Patterns   │    │  - Time      │    │  - Notify │ │
│  │  - nginx     │    │  - Anomalies  │    │  - Top N     │    │  - Cooldown│
│  │  - Syslog    │    │  - Reports    │    │  - Percentile│   │  - History│
│  │  - Custom    │    │              │    │              │    │           │ │
│  │              │    │              │    │              │    │           │ │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └─────┬─────┘ │
│         │                   │                   │                   │       │
│         └───────────────────┼───────────────────┼───────────────────┘       │
│                             │                   │                            │
│                             ▼                   ▼                            │
│                    ┌─────────────────┐  ┌─────────────────┐                   │
│                    │  ParsedEntry    │  │ AggregatedMetric│                   │
│                    │    objects      │  │   objects      │                   │
│                    └─────────────────┘  └─────────────────┘                   │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Formatter Layer                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌────────┐  ┌────────┐              │
│  │   JSON  │  │  Apache  │  │ nginx  │  │ Syslog │  │ Custom │              │
│  │Formatter│  │ Formatter│  │Formatter│ │ Formatter│ │ Formatter│             │
│  └─────────┘  └──────────┘  └────────┘  └────────┘  └────────┘              │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Pattern Layer                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐                         │
│  │  PatternMatcher     │    │   PatternRegistry   │                         │
│  │  - match()          │    │   - add_pattern()   │                         │
│  │  - search()         │    │   - remove_pattern()│                         │
│  │  - extract()       │    │   - get_pattern()   │                         │
│  │  - match_all()     │    │   - list_patterns() │                         │
│  └─────────────────────┘    └─────────────────────┘                         │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Configuration                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        LogParserConfig                               │    │
│  │  - encoding          - timestamp_formats    - aggregation_settings   │    │
│  │  - chunk_size        - field_mapping       - alert_settings          │    │
│  │  - strict_mode       - error_handling       - performance_monitoring  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Descriptions

| Component | Purpose | Key Classes |
|-----------|---------|-------------|
| **Parser** | Parse raw log data into structured entries | `LogParser`, `ParsedEntry`, `ParseResult` |
| **Analyzer** | Statistical analysis and anomaly detection | `LogAnalyzer`, `LogStatistics`, `Anomaly` |
| **Aggregator** | Data aggregation and metrics | `LogAggregator`, `AggregatedMetric`, `AggregationResult` |
| **Alerter** | Rule-based alerting and notifications | `LogAlerter`, `Alert`, `AlertRule`, `AlertEvent` |
| **Formatters** | Format-specific parsing logic | `BaseFormatter`, `JSONFormatter`, `ApacheFormatter`, etc. |
| **Patterns** | Pattern matching and extraction | `PatternMatcher`, `PatternRegistry`, `Pattern` |
| **Config** | Configuration management | `LogParserConfig`, presets |

---

## Supported Formats

### 1. JSON Logs

Structured JSON logs with flexible field mapping:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "Server started",
  "service": "api-gateway",
  "metadata": {}
}
```

**Supported JSON field names:**
- Timestamp: `timestamp`, `time`, `@timestamp`, `ts`, `datetime`, `date`
- Level: `level`, `severity`, `log_level`, `loglevel`, `lvl`
- Message: `message`, `msg`, `text`, `log`, `description`
- Source: `source`, `logger`, `logger_name`, `service`, `component`

### 2. Apache Logs

**Common Log Format:**
```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```

**Combined Log Format:**
```
127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.1" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08"
```

### 3. nginx Logs

**Access Log:**
```
192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
```

**Error Log:**
```
2024/01/15 10:30:00 [error] 1234#5678: *1 connect() failed to 127.0.0.1:8080
```

### 4. Syslog

**BSD Format:**
```
Jan 15 10:30:00 server sshd[12345]: Accepted publickey for user
```

**RFC 3164 Format (with priority):**
```
<34>Jan 15 10:30:00 server sshd[12345]: Accepted publickey for user
```

### 5. Custom Formats

```python
from logparser import LogParser, LogFormat

# Using custom regex pattern
parser = LogParser(
    format=LogFormat.CUSTOM,
    custom_pattern=r'^(?P<timestamp>\S+)\s+(?P<level>\w+)\s+(?P<message>.*)$'
)
```

---

## Installation

### Requirements

- Python 3.8 or higher
- No external dependencies for core functionality

### Using pip

```bash
# Install latest release
pip install logparser

# Install with optional dependencies
pip install logparser[pandas]  # For DataFrame export

# Install development version
pip install git+https://github.com/moggan1337/LogParser.git
```

### From Source

```bash
# Clone repository
git clone https://github.com/moggan1337/LogParser.git
cd LogParser

# Install in development mode
pip install -e ".[dev]"

# Or install with optional dependencies
pip install -e ".[pandas,dev]"
```

### Verify Installation

```python
import logparser
print(logparser.__version__)  # 1.0.0
```

---

## Quick Start

### Basic Parsing

```python
from logparser import LogParser, LogFormat

# Create parser
parser = LogParser(format=LogFormat.JSON)

# Parse a single line
entry = parser.parse_line('{"level": "INFO", "message": "Hello World"}')
print(f"[{entry.level}] {entry.message}")

# Parse a file
result = parser.parse_file("access.log")
print(f"Parsed {result.parsed_lines} of {result.total_lines} lines")
```

### Analyzing Logs

```python
from logparser import LogParser, LogAnalyzer, LogFormat

parser = LogParser(format=LogFormat.JSON)
result = parser.parse_file("application.log")

analyzer = LogAnalyzer()
stats = analyzer.get_statistics(result.entries)

print(f"Total entries: {stats.total_entries}")
print(f"Error rate: {stats.error_rate:.2f}%")
print(f"Unique messages: {stats.unique_messages}")

# Generate full report
report = analyzer.generate_report(result.entries)
print(report)
```

### Setting Up Alerts

```python
from logparser import LogParser, LogAlerter, LogFormat, AlertSeverity

parser = LogParser(format=LogFormat.JSON)
result = parser.parse_file("application.log")

alerter = LogAlerter()
alerter.add_rule(
    name="critical_errors",
    condition="level == 'ERROR'",
    severity=AlertSeverity.CRITICAL,
    match_count=3
)

events = alerter.process_entries(result.entries)
print(f"Alerts triggered: {events.total_triggered}")
```

---

## Usage Examples

### 1. Parse and Analyze JSON Logs

```python
import json
from logparser import LogParser, LogAnalyzer, LogFormat

# Initialize parser
parser = LogParser(format=LogFormat.JSON)
analyzer = LogAnalyzer()

# Parse log file
result = parser.parse_file("api.log")

# Get statistics
stats = analyzer.get_statistics(result.entries)
print(f"Total: {stats.total_entries}, Errors: {stats.error_rate:.1f}%")

# Detect anomalies
anomalies = analyzer.detect_anomalies(result.entries)
for anomaly in anomalies:
    print(f"[{anomaly.severity}] {anomaly.description}")
```

### 2. Parse Apache Access Logs

```python
from logparser import LogParser, LogFormat

parser = LogParser(format=LogFormat.APACHE_COMBINED)
result = parser.parse_file("access.log")

# Extract metrics
status_codes = {}
for entry in result.entries:
    status = entry.metadata.get("status", 0)
    status_codes[status] = status_codes.get(status, 0) + 1

print(f"200 OK: {status_codes.get(200, 0)}")
print(f"404 Not Found: {status_codes.get(404, 0)}")
print(f"500 Error: {status_codes.get(500, 0)}")
```

### 3. Stream Large Files

```python
from logparser import LogParser, LogFormat

parser = LogParser(format=LogFormat.JSON)

# Process large file without loading into memory
entries = []
def process_entry(entry):
    entries.append(entry)
    # Process each entry here

result = parser.parse_stream("large.log", process_entry)
print(f"Processed {result.total_lines} lines in {result.parse_time:.2f}s")
```

### 4. Aggregate by Time Window

```python
from logparser import LogParser, LogAggregator, LogFormat
from datetime import datetime

parser = LogParser(format=LogFormat.JSON)
result = parser.parse_file("application.log")

aggregator = LogAggregator()

# Aggregate by hour
hourly = aggregator.aggregate_by_time(result.entries, interval="hour")

# Aggregate by field
by_level = aggregator.aggregate_by_field(result.entries, field="level")

# Top 5 error sources
top_errors = aggregator.top_n(
    [e for e in result.entries if e.level == "ERROR"],
    field="source",
    n=5
)
```

### 5. Configure Alert Rules

```python
from logparser import LogParser, LogAlerter, LogFormat, AlertSeverity

parser = LogParser(format=LogFormat.JSON)
alerter = LogAlerter()

# Multiple alert rules
alerter.add_rule(
    name="critical",
    condition="level == 'CRITICAL'",
    severity=AlertSeverity.CRITICAL,
    match_count=1
)

alerter.add_rule(
    name="high_error",
    condition="level == 'ERROR'",
    severity=AlertSeverity.ERROR,
    match_count=5,
    cooldown_seconds=300
)

alerter.add_rule(
    name="authentication_failure",
    condition="message contains 'Authentication failed'",
    severity=AlertSeverity.WARNING,
    match_count=3
)

# Process and get alerts
result = parser.parse_file("auth.log")
events = alerter.process_entries(result.entries)

for alert in events.alerts:
    print(f"[{alert.severity.value}] {alert.message}")
```

### 6. Using Custom Patterns

```python
from logparser.patterns import PatternMatcher, PatternRegistry

registry = PatternRegistry()

# Add custom pattern
registry.add_pattern(
    name="custom_id",
    pattern=r"ID[:\s]+([A-Z0-9-]{36})",
    description="Custom UUID format",
    fields=["custom_id"]
)

matcher = PatternMatcher(registry)

# Match in text
result = matcher.match("Order ID: 550e8400-e29b-41d4-a716-446655440000 processed")
print(result.groups)  # {'custom_id': '550e8400-e29b-41d4-a716-446655440000'}
```

---

## API Reference

### LogParser

```python
class LogParser:
    def __init__(
        self,
        format: Union[LogFormat, str] = LogFormat.AUTO,
        config: Optional[LogParserConfig] = None,
        pattern_matcher: Optional[PatternMatcher] = None,
        custom_pattern: Optional[str] = None,
        encoding: str = "utf-8",
        strict: bool = False,
    )
```

**Methods:**

| Method | Description | Returns |
|--------|-------------|---------|
| `parse_line(line)` | Parse single log line | `Optional[ParsedEntry]` |
| `parse_string(content)` | Parse multi-line string | `ParseResult` |
| `parse_file(path)` | Parse entire file | `ParseResult` |
| `parse_stream(path, callback)` | Stream parse with callback | `ParseResult` |
| `parse_iter(path)` | Iterator for memory-efficient parsing | `Iterator[ParsedEntry]` |

### ParsedEntry

```python
@dataclass
class ParsedEntry:
    timestamp: Optional[datetime]  # Parsed timestamp
    level: Optional[str]          # Log level (INFO, ERROR, etc.)
    message: str                  # Main log message
    source: Optional[str]         # Source/service name
    raw: str                      # Raw log line
    metadata: Dict[str, Any]     # Additional extracted fields
```

### LogAnalyzer

```python
class LogAnalyzer:
    def __init__(self, sensitivity: float = 1.5)
    
    def get_statistics(entries: List[ParsedEntry]) -> LogStatistics
    def detect_anomalies(entries: List[ParsedEntry]) -> List[Anomaly]
    def analyze_patterns(entries: List[ParsedEntry]) -> Dict[str, Any]
    def generate_report(entries: List[ParsedEntry]) -> str
```

### LogAggregator

```python
class LogAggregator:
    def aggregate_by_field(
        entries: List[ParsedEntry],
        field: str,
        metric: AggregationType = AggregationType.COUNT
    ) -> AggregationResult
    
    def aggregate_by_time(
        entries: List[ParsedEntry],
        interval: str = "hour"
    ) -> AggregationResult
    
    def top_n(entries: List[ParsedEntry], field: str, n: int = 10) -> List[AggregatedMetric]
```

### LogAlerter

```python
class LogAlerter:
    def __init__(self)
    
    def add_rule(
        name: str,
        condition: str,
        severity: AlertSeverity = AlertSeverity.WARNING,
        cooldown_seconds: int = 300,
        match_count: int = 1
    ) -> None
    
    def process_entries(entries: List[ParsedEntry]) -> AlertEvent
    def get_active_alerts() -> List[Alert]
    def get_alert_history(limit: int = 100) -> List[Alert]
```

---

## Configuration

### Default Configuration

```python
from logparser.config import LogParserConfig

config = LogParserConfig(
    # Encoding
    encoding="utf-8",
    encoding_errors="replace",
    
    # Performance
    chunk_size=1000,
    max_line_length=65536,
    buffer_size=8192,
    
    # Parsing behavior
    strict_mode=False,
    skip_invalid_lines=True,
    auto_detect_format=True,
    
    # Output
    include_raw=True,
    include_metadata=True,
    datetime_format="iso",
)
```

### Presets

```python
from logparser.config import get_preset

# Performance-focused
config = get_preset("performance")

# Strict parsing
config = get_preset("strict")

# Debugging
config = get_preset("debugging")

# Production
config = get_preset("production")
```

### Environment Variables

```bash
export LOGPARSER_CHUNK_SIZE=5000
export LOGPARSER_ENCODING=utf-16
export LOGPARSER_STRICT_MODE=false
```

### Configuration File

```json
{
  "encoding": "utf-8",
  "chunk_size": 2000,
  "strict_mode": false,
  "skip_invalid_lines": true,
  "auto_detect_format": true,
  "timestamp_formats": [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S"
  ],
  "aggregation_window": "hour"
}
```

---

## Performance Benchmarks

Tests run on MacBook Pro M2, 16GB RAM, Python 3.11

| Operation | 100 lines | 1,000 lines | 10,000 lines | 100,000 lines |
|-----------|-----------|-------------|--------------|---------------|
| JSON Parse | ~1ms | ~10ms | ~100ms | ~1s |
| Apache Parse | ~1ms | ~8ms | ~80ms | ~800ms |
| File Parse | ~2ms | ~15ms | ~150ms | ~1.5s |
| Streaming | ~3ms | ~20ms | ~200ms | ~2s |
| Analysis | ~2ms | ~15ms | ~150ms | ~1.5s |
| Aggregation | ~1ms | ~10ms | ~100ms | ~1s |

### Throughput

| Format | Lines/Second | MB/Second (estimated) |
|--------|--------------|---------------------|
| JSON | ~100,000 | ~5-10 MB/s |
| Apache | ~125,000 | ~8-12 MB/s |
| nginx | ~130,000 | ~8-12 MB/s |
| Syslog | ~110,000 | ~6-10 MB/s |

### Memory Usage

| Mode | File Size | Memory Usage |
|------|-----------|--------------|
| Batch | 100 MB | ~50-100 MB |
| Streaming | 100 MB | ~5-10 MB |
| Iterator | 100 MB | ~1-5 MB |

### Optimization Tips

1. **Use streaming for large files**: `parse_stream()` or `parse_iter()` for files >100MB
2. **Specify format explicitly**: Avoid auto-detection overhead
3. **Adjust chunk_size**: Larger values for more throughput, smaller for less memory
4. **Enable skip_invalid_lines**: Faster parsing of noisy logs
5. **Use appropriate encoding**: Match your file encoding to avoid transcoding

---

## Troubleshooting

### Common Issues

#### 1. Encoding Errors

```python
# Problem: UnicodeDecodeError when parsing file
# Solution: Specify correct encoding

parser = LogParser(encoding="utf-8")  # or "latin-1", "cp1252", etc.
```

#### 2. Low Success Rate

```python
# Problem: Many lines fail to parse
# Solution: Check log format matches

# If format is mixed, use AUTO detection
parser = LogParser(format=LogFormat.AUTO)

# Or specify correct format
parser = LogParser(format=LogFormat.APACHE_COMBINED)
```

#### 3. Memory Issues with Large Files

```python
# Problem: Out of memory when parsing large files
# Solution: Use streaming parser

parser = LogParser()
result = parser.parse_stream("huge.log", callback=process_entry)

# Or use iterator
for entry in parser.parse_iter("huge.log"):
    process_entry(entry)
```

#### 4. Slow Parsing Performance

```python
# Problem: Parsing is slower than expected
# Solution: Optimize configuration

config = LogParserConfig(
    chunk_size=5000,           # Increase for more throughput
    skip_invalid_lines=True,   # Skip bad lines faster
)
parser = LogParser(config=config)
```

#### 5. Alert Cooldown Issues

```python
# Problem: Too many or too few alerts
# Solution: Adjust cooldown

alerter.add_rule(
    name="my_rule",
    condition="level == 'ERROR'",
    cooldown_seconds=60,  # Reduce for more alerts, increase for fewer
    match_count=1         # Adjust trigger threshold
)
```

### Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

from logparser import LogParser
parser = LogParser()
# Will show detailed parsing information
```

### Getting Help

```bash
# Run tests
pytest tests/ -v

# Run specific test
pytest tests/test_logparser.py::TestLogParser::test_parse_json_line -v

# Generate sample logs
python examples/sample_logs.py

# Run benchmarks
python benchmarks/benchmark.py
```

---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

### Development Setup

```bash
# Clone and install
git clone https://github.com/moggan1337/LogParser.git
cd LogParser
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=logparser

# Format code
black logparser/

# Type check
mypy logparser/
```

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**LogParser** - Built with ❤️ for the developer community

[Back to Top](#logparser---advanced-log-parsing-and-analysis-engine)

</div>
