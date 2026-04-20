"""
Core Log Parser Module

Provides the main LogParser class for parsing various log formats with
support for streaming and batch processing.
"""

import re
import json
from typing import Dict, List, Optional, Any, Union, Iterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
import logging

from .formatters import (
    BaseFormatter, 
    JSONFormatter, 
    ApacheFormatter, 
    NginxFormatter, 
    SyslogFormatter,
    get_formatter
)
from .patterns import PatternMatcher, PatternRegistry
from .config import LogParserConfig

logger = logging.getLogger(__name__)


class LogFormat(Enum):
    """Supported log formats."""
    AUTO = "auto"
    JSON = "json"
    APACHE_COMMON = "apache_common"
    APACHE_COMBINED = "apache_combined"
    NGINX = "nginx"
    SYSLOG = "syslog"
    CUSTOM = "custom"


class ParseError(Exception):
    """Exception raised when log parsing fails."""
    pass


class FormatDetectionError(Exception):
    """Exception raised when log format cannot be detected."""
    pass


@dataclass
class ParsedEntry:
    """Represents a single parsed log entry."""
    timestamp: Optional[datetime] = None
    level: Optional[str] = None
    message: str = ""
    source: Optional[str] = None
    raw: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "message": self.message,
            "source": self.source,
            "raw": self.raw,
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        """Convert entry to JSON string."""
        return json.dumps(self.to_dict(), default=str)


@dataclass
class ParseResult:
    """Container for parsing results with statistics."""
    entries: List[ParsedEntry] = field(default_factory=list)
    total_lines: int = 0
    parsed_lines: int = 0
    failed_lines: int = 0
    errors: List[str] = field(default_factory=list)
    parse_time: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate parsing success rate."""
        if self.total_lines == 0:
            return 0.0
        return (self.parsed_lines / self.total_lines) * 100
    
    def add_entry(self, entry: ParsedEntry) -> None:
        """Add a parsed entry."""
        self.entries.append(entry)
        self.parsed_lines += 1
    
    def add_error(self, line: str, error: str) -> None:
        """Record a parsing error."""
        self.failed_lines += 1
        self.errors.append(f"Line {self.total_lines}: {error}")


class LogParser:
    """
    Main log parser class supporting multiple formats.
    
    Supports:
    - JSON logs (structured logging)
    - Apache Common/Combined logs
    - nginx access/error logs
    - Syslog format
    - Custom patterns
    
    Example:
        >>> parser = LogParser(format=LogFormat.AUTO)
        >>> result = parser.parse_file("access.log")
        >>> for entry in result.entries:
        ...     print(entry.message)
    """
    
    # Default patterns for format detection
    DETECTION_PATTERNS = {
        LogFormat.JSON: r'^\s*\{.*\}\s*$',
        LogFormat.APACHE_COMMON: r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"',
        LogFormat.APACHE_COMBINED: r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"',
        LogFormat.NGINX: r'^(\S+)\s+-\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"',
        LogFormat.SYSLOG: r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)',
    }
    
    def __init__(
        self,
        format: Union[LogFormat, str] = LogFormat.AUTO,
        config: Optional[LogParserConfig] = None,
        pattern_matcher: Optional[PatternMatcher] = None,
        custom_pattern: Optional[str] = None,
        encoding: str = "utf-8",
        strict: bool = False,
    ):
        """
        Initialize the LogParser.
        
        Args:
            format: Log format to use (auto-detect by default)
            config: Parser configuration
            pattern_matcher: Custom pattern matcher instance
            custom_pattern: Custom regex pattern for parsing
            encoding: File encoding (default: utf-8)
            strict: If True, raise exceptions on parse errors
        """
        self.format = LogFormat(format) if isinstance(format, str) else format
        self.config = config or LogParserConfig()
        self.pattern_matcher = pattern_matcher or PatternMatcher()
        self.custom_pattern = custom_pattern
        self.encoding = encoding
        self.strict = strict
        
        self._formatter: Optional[BaseFormatter] = None
        self._detected_format: Optional[LogFormat] = None
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficient parsing."""
        self._patterns: Dict[LogFormat, re.Pattern] = {}
        
        for fmt, pattern in self.DETECTION_PATTERNS.items():
            self._patterns[fmt] = re.compile(pattern)
        
        if self.custom_pattern:
            self._patterns[LogFormat.CUSTOM] = re.compile(self.custom_pattern)
    
    def _detect_format(self, sample: List[str]) -> LogFormat:
        """
        Auto-detect log format from sample lines.
        
        Args:
            sample: List of log lines to analyze
            
        Returns:
            Detected LogFormat
            
        Raises:
            FormatDetectionError: If format cannot be determined
        """
        scores: Dict[LogFormat, int] = {fmt: 0 for fmt in LogFormat}
        
        for line in sample:
            for fmt, pattern in self._patterns.items():
                if fmt == LogFormat.AUTO or fmt == LogFormat.CUSTOM:
                    continue
                if pattern.match(line.strip()):
                    scores[fmt] += 1
        
        # Find format with highest score
        detected = max(scores.items(), key=lambda x: x[1])
        
        if detected[1] == 0:
            raise FormatDetectionError(
                "Could not detect log format. Please specify format manually."
            )
        
        return detected[0]
    
    def _get_formatter(self, fmt: Optional[LogFormat] = None) -> BaseFormatter:
        """Get formatter for the specified or detected format."""
        target_format = fmt or self._detected_format or LogFormat.JSON
        return get_formatter(target_format)
    
    def parse_line(self, line: str) -> Optional[ParsedEntry]:
        """
        Parse a single log line.
        
        Args:
            line: Log line to parse
            
        Returns:
            ParsedEntry or None if parsing fails
        """
        line = line.strip()
        if not line:
            return None
        
        try:
            # Try JSON first if format is auto
            if self.format == LogFormat.AUTO or self.format == LogFormat.JSON:
                try:
                    data = json.loads(line)
                    formatter = self._get_formatter(LogFormat.JSON)
                    return formatter.parse(data, raw=line)
                except json.JSONDecodeError:
                    pass
            
            # Try format-specific parsing
            formatter = self._get_formatter(self.format)
            return formatter.parse(line, raw=line)
            
        except Exception as e:
            if self.strict:
                raise ParseError(f"Failed to parse line: {e}")
            logger.debug(f"Parse error: {e}")
            return None
    
    def parse_string(self, content: str) -> ParseResult:
        """
        Parse log content from a string.
        
        Args:
            content: Log content as string
            
        Returns:
            ParseResult with all parsed entries
        """
        import time
        result = ParseResult()
        start_time = time.time()
        
        lines = content.split("\n")
        result.total_lines = len(lines)
        
        for line in lines:
            if entry := self.parse_line(line):
                result.add_entry(entry)
            else:
                result.add_error(line, "Failed to parse line")
        
        result.parse_time = time.time() - start_time
        return result
    
    def parse_file(
        self,
        path: Union[str, Path],
        detect_format: bool = True,
        sample_size: int = 100,
    ) -> ParseResult:
        """
        Parse a log file.
        
        Args:
            path: Path to log file
            detect_format: Whether to auto-detect format (requires reading sample)
            sample_size: Number of lines to use for format detection
            
        Returns:
            ParseResult with all parsed entries
        """
        import time
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        
        result = ParseResult()
        start_time = time.time()
        
        # Auto-detect format if requested
        if detect_format and self.format == LogFormat.AUTO:
            with open(path, "r", encoding=self.encoding) as f:
                sample = [f.readline() for _ in range(sample_size) if f.readline()]
            try:
                self._detected_format = self._detect_format(sample)
                logger.info(f"Detected format: {self._detected_format}")
            except FormatDetectionError:
                logger.warning("Could not auto-detect format, using default")
        
        # Parse file
        with open(path, "r", encoding=self.encoding) as f:
            for line in f:
                result.total_lines += 1
                if entry := self.parse_line(line):
                    result.add_entry(entry)
                elif line.strip():
                    result.add_error(line, "Failed to parse")
        
        result.parse_time = time.time() - start_time
        return result
    
    def parse_stream(
        self,
        path: Union[str, Path],
        callback: Callable[[ParsedEntry], None],
        batch_size: int = 1000,
    ) -> ParseResult:
        """
        Parse a log file with streaming (memory efficient).
        
        Args:
            path: Path to log file
            callback: Function to call for each parsed entry
            batch_size: Number of entries to collect before yielding
            
        Returns:
            ParseResult with statistics
        """
        import time
        path = Path(path)
        result = ParseResult()
        start_time = time.time()
        
        with open(path, "r", encoding=self.encoding) as f:
            for line in f:
                result.total_lines += 1
                if entry := self.parse_line(line):
                    result.add_entry(entry)
                    callback(entry)
                elif line.strip():
                    result.add_error(line, "Failed to parse")
        
        result.parse_time = time.time() - start_time
        return result
    
    def parse_iter(self, path: Union[str, Path]) -> Iterator[ParsedEntry]:
        """
        Create an iterator for parsing log lines.
        
        Args:
            path: Path to log file
            
        Yields:
            ParsedEntry for each valid log line
        """
        path = Path(path)
        with open(path, "r", encoding=self.encoding) as f:
            for line in f:
                if entry := self.parse_line(line):
                    yield entry
