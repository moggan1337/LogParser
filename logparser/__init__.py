"""
LogParser - Advanced Log Parsing and Analysis Engine

A high-performance, extensible log parsing library supporting multiple formats
including JSON, Apache, nginx, and syslog logs with pattern matching,
structured parsing, aggregation, and alerting capabilities.

Author: LogParser Team
License: MIT
"""

__version__ = "1.0.0"
__author__ = "LogParser Team"

from .parser import LogParser
from .analyzer import LogAnalyzer
from .aggregator import LogAggregator
from .alerter import LogAlerter
from .formatters import JSONFormatter, ApacheFormatter, NginxFormatter, SyslogFormatter
from .patterns import PatternMatcher, PatternRegistry
from .config import LogParserConfig

__all__ = [
    "LogParser",
    "LogAnalyzer", 
    "LogAggregator",
    "LogAlerter",
    "JSONFormatter",
    "ApacheFormatter",
    "NginxFormatter",
    "SyslogFormatter",
    "PatternMatcher",
    "PatternRegistry",
    "LogParserConfig",
]
