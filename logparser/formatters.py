"""
Log Formatters Module

Provides formatters for different log formats including
JSON, Apache, nginx, and syslog.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import re
import json

from .parser import ParsedEntry, LogFormat


class BaseFormatter(ABC):
    """Abstract base class for log formatters."""
    
    @abstractmethod
    def parse(self, line: Union[str, Dict], raw: str = "") -> Optional[ParsedEntry]:
        """
        Parse a log line into a ParsedEntry.
        
        Args:
            line: Log line to parse (string or dict for JSON)
            raw: Raw log line for reference
            
        Returns:
            ParsedEntry or None if parsing fails
        """
        pass
    
    @abstractmethod
    def format(self, entry: ParsedEntry) -> str:
        """
        Format a ParsedEntry back to string.
        
        Args:
            entry: ParsedEntry to format
            
        Returns:
            Formatted log line
        """
        pass


class JSONFormatter(BaseFormatter):
    """Formatter for JSON-structured logs."""
    
    # Common JSON log field mappings
    FIELD_MAPPINGS = {
        "timestamp": ["timestamp", "time", "@timestamp", "ts", "datetime", "date"],
        "level": ["level", "severity", "log_level", "loglevel", "lvl"],
        "message": ["message", "msg", "text", "log", "description"],
        "source": ["source", "logger", "logger_name", "service", "component"],
    }
    
    def __init__(self, field_mapping: Optional[Dict[str, str]] = None):
        """
        Initialize JSON formatter.
        
        Args:
            field_mapping: Custom field mapping for JSON keys
        """
        self.field_mapping = field_mapping or {}
    
    def parse(self, data: Union[str, Dict], raw: str = "") -> Optional[ParsedEntry]:
        """Parse a JSON log line."""
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                return None
        
        if not isinstance(data, dict):
            return None
        
        # Extract standard fields using mappings
        timestamp = self._extract_field(data, "timestamp")
        level = self._extract_field(data, "level")
        message = self._extract_field(data, "message")
        source = self._extract_field(data, "source")
        
        # Build metadata from remaining fields
        metadata = {}
        standard_fields = {"timestamp", "level", "message", "source", "time", 
                          "@timestamp", "ts", "datetime", "date", "severity",
                          "log_level", "loglevel", "lvl", "msg", "text", "log",
                          "description", "logger", "logger_name", "service", "component"}
        
        for key, value in data.items():
            if key not in standard_fields:
                metadata[key] = value
        
        # Parse timestamp if it's a string
        if isinstance(timestamp, str):
            timestamp = self._parse_timestamp(timestamp)
        
        return ParsedEntry(
            timestamp=timestamp,
            level=level,
            message=message or "",
            source=source,
            raw=raw or json.dumps(data),
            metadata=metadata,
        )
    
    def format(self, entry: ParsedEntry) -> str:
        """Format a ParsedEntry to JSON."""
        data = {}
        
        if entry.timestamp:
            data["timestamp"] = entry.timestamp.isoformat()
        if entry.level:
            data["level"] = entry.level
        if entry.message:
            data["message"] = entry.message
        if entry.source:
            data["source"] = entry.source
        data.update(entry.metadata)
        
        return json.dumps(data)
    
    def _extract_field(self, data: Dict, field: str) -> Optional[str]:
        """Extract field from data using mappings."""
        # Check custom mapping first
        if field in self.field_mapping:
            key = self.field_mapping[field]
            if key in data:
                return str(data[key])
        
        # Check standard mappings
        if field in self.FIELD_MAPPINGS:
            for possible_key in self.FIELD_MAPPINGS[field]:
                if possible_key in data:
                    value = data[possible_key]
                    return str(value) if value is not None else None
        
        # Direct lookup
        if field in data:
            value = data[field]
            return str(value) if value is not None else None
        
        return None
    
    def _parse_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse various timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d/%b/%Y:%H:%M:%S %z",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        
        # Try ISO format
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pass
        
        return None


class ApacheFormatter(BaseFormatter):
    """Formatter for Apache Common/Combined log format."""
    
    # Apache Common Log Format pattern
    COMMON_PATTERN = re.compile(
        r'^(?P<host>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>\S+)'
    )
    
    # Apache Combined adds referrer and user-agent
    COMBINED_PATTERN = re.compile(
        r'^(?P<host>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>\S+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )
    
    def __init__(self, combined: bool = False):
        """
        Initialize Apache formatter.
        
        Args:
            combined: Use combined format (with referrer and user-agent)
        """
        self.combined = combined
        self.pattern = self.COMBINED_PATTERN if combined else self.COMMON_PATTERN
    
    def parse(self, line: str, raw: str = "") -> Optional[ParsedEntry]:
        """Parse an Apache log line."""
        match = self.pattern.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp_str = data.get("timestamp", "")
        timestamp = self._parse_apache_timestamp(timestamp_str)
        
        # Determine level from status code
        status = int(data.get("status", 0))
        level = self._status_to_level(status)
        
        # Extract request method
        request = data.get("request", "")
        method = request.split()[0] if request else ""
        
        # Extract path
        path = request.split()[1] if len(request.split()) > 1 else ""
        
        # Build metadata
        metadata = {
            "host": data.get("host"),
            "ident": data.get("ident"),
            "user": data.get("user"),
            "status": status,
            "bytes": data.get("bytes"),
            "method": method,
            "path": path,
            "request": request,
        }
        
        if self.combined:
            metadata["referrer"] = data.get("referrer")
            metadata["user_agent"] = data.get("user_agent")
        
        return ParsedEntry(
            timestamp=timestamp,
            level=level,
            message=request or "",
            source=data.get("host"),
            raw=raw or line,
            metadata=metadata,
        )
    
    def format(self, entry: ParsedEntry) -> str:
        """Format a ParsedEntry to Apache log format."""
        host = entry.metadata.get("host", "-")
        ident = entry.metadata.get("ident", "-")
        user = entry.metadata.get("user", "-")
        timestamp = entry.timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000") if entry.timestamp else "-"
        request = entry.message or "-"
        status = entry.metadata.get("status", 200)
        bytes_sent = entry.metadata.get("bytes", "-")
        
        if self.combined:
            referrer = entry.metadata.get("referrer", "-")
            user_agent = entry.metadata.get("user_agent", "-")
            return f'{host} {ident} {user} [{timestamp}] "{request}" {status} {bytes_sent} "{referrer}" "{user_agent}"'
        
        return f'{host} {ident} {user} [{timestamp}] "{request}" {status} {bytes_sent}'
    
    def _parse_apache_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse Apache timestamp format."""
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None
    
    def _status_to_level(self, status: int) -> str:
        """Convert HTTP status code to log level."""
        if status >= 500:
            return "ERROR"
        elif status >= 400:
            return "WARNING"
        elif status >= 300:
            return "INFO"
        return "INFO"


class NginxFormatter(BaseFormatter):
    """Formatter for nginx access and error logs."""
    
    # nginx access log pattern (similar to Apache)
    ACCESS_PATTERN = re.compile(
        r'^(?P<host>\S+)\s+-\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>\S+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )
    
    # nginx error log pattern
    ERROR_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'(?P<pid>\d+)#(?P<cid>\d+):\s*'
        r'(?P<message>.*)'
    )
    
    def __init__(self, error_log: bool = False):
        """
        Initialize nginx formatter.
        
        Args:
            error_log: Parse as error log format
        """
        self.error_log = error_log
    
    def parse(self, line: str, raw: str = "") -> Optional[ParsedEntry]:
        """Parse an nginx log line."""
        if self.error_log:
            return self._parse_error_log(line, raw)
        return self._parse_access_log(line, raw)
    
    def _parse_access_log(self, line: str, raw: str = "") -> Optional[ParsedEntry]:
        """Parse nginx access log line."""
        match = self.ACCESS_PATTERN.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_nginx_timestamp(data.get("timestamp", ""))
        
        # Status to level
        status = int(data.get("status", 0))
        level = self._status_to_level(status)
        
        # Parse request
        request = data.get("request", "")
        method = request.split()[0] if request else ""
        path = request.split()[1] if len(request.split()) > 1 else ""
        
        metadata = {
            "host": data.get("host"),
            "user": data.get("user"),
            "status": status,
            "bytes": data.get("bytes"),
            "referrer": data.get("referrer"),
            "user_agent": data.get("user_agent"),
            "method": method,
            "path": path,
        }
        
        return ParsedEntry(
            timestamp=timestamp,
            level=level,
            message=request or "",
            source=data.get("host"),
            raw=raw or line,
            metadata=metadata,
        )
    
    def _parse_error_log(self, line: str, raw: str = "") -> Optional[ParsedEntry]:
        """Parse nginx error log line."""
        match = self.ERROR_PATTERN.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_nginx_error_timestamp(data.get("timestamp", ""))
        
        # Map level
        nginx_level = data.get("level", "info").upper()
        level = self._nginx_level_to_standard(nginx_level)
        
        metadata = {
            "pid": int(data.get("pid", 0)) if data.get("pid") else None,
            "cid": int(data.get("cid", 0)) if data.get("cid") else None,
        }
        
        return ParsedEntry(
            timestamp=timestamp,
            level=level,
            message=data.get("message", ""),
            source="nginx",
            raw=raw or line,
            metadata=metadata,
        )
    
    def format(self, entry: ParsedEntry) -> str:
        """Format a ParsedEntry to nginx log format."""
        host = entry.metadata.get("host", "-")
        user = entry.metadata.get("user", "-")
        timestamp = entry.timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000") if entry.timestamp else "-"
        request = entry.message or "-"
        status = entry.metadata.get("status", 200)
        bytes_sent = entry.metadata.get("bytes", "-")
        referrer = entry.metadata.get("referrer", "-")
        user_agent = entry.metadata.get("user_agent", "-")
        
        return f'{host} - {user} [{timestamp}] "{request}" {status} {bytes_sent} "{referrer}" "{user_agent}"'
    
    def _parse_nginx_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse nginx timestamp."""
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None
    
    def _parse_nginx_error_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse nginx error log timestamp."""
        try:
            return datetime.strptime(ts, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
    
    def _status_to_level(self, status: int) -> str:
        """Convert HTTP status code to log level."""
        if status >= 500:
            return "ERROR"
        elif status >= 400:
            return "WARNING"
        return "INFO"
    
    def _nginx_level_to_standard(self, level: str) -> str:
        """Map nginx log level to standard level."""
        mapping = {
            "DEBUG": "DEBUG",
            "INFO": "INFO",
            "NOTICE": "INFO",
            "WARN": "WARNING",
            "WARNING": "WARNING",
            "ERROR": "ERROR",
            "CRIT": "CRITICAL",
            "ALERT": "CRITICAL",
            "EMERG": "CRITICAL",
        }
        return mapping.get(level, "INFO")


class SyslogFormatter(BaseFormatter):
    """Formatter for syslog format."""
    
    # BSD syslog pattern
    BSD_PATTERN = re.compile(
        r'^(?P<month>\w{3})\s+'
        r'(?P<day>\d{1,2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<program>\S+?)'
        r'(?:\[(?P<pid>\d+)\])?\s*:\s*'
        r'(?P<message>.*)'
    )
    
    # RFC 3164 syslog pattern
    RFC3164_PATTERN = re.compile(
        r'^<(?P<priority>\d+)>'
        r'(?P<month>\w{3})\s+'
        r'(?P<day>\d{1,2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+'
        r'(?P<program>\S+?)'
        r'(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)'
    )
    
    def __init__(self, use_rfc3164: bool = False):
        """
        Initialize syslog formatter.
        
        Args:
            use_rfc3164: Use RFC 3164 format (with priority)
        """
        self.use_rfc3164 = use_rfc3164
        self.pattern = self.RFC3164_PATTERN if use_rfc3164 else self.BSD_PATTERN
    
    def parse(self, line: str, raw: str = "") -> Optional[ParsedEntry]:
        """Parse a syslog line."""
        match = self.pattern.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_timestamp(
            data.get("month", ""),
            data.get("day", ""),
            data.get("time", "")
        )
        
        # Extract level from priority or message
        priority = data.get("priority")
        level = self._priority_to_level(int(priority)) if priority else None
        
        # Try to extract level from message
        if not level:
            level = self._extract_level_from_message(data.get("message", ""))
        
        metadata = {
            "host": data.get("host"),
            "program": data.get("program"),
            "pid": int(data.get("pid")) if data.get("pid") else None,
        }
        
        if priority:
            metadata["priority"] = int(priority)
            metadata["facility"] = int(priority) >> 3
            metadata["severity"] = int(priority) & 7
        
        return ParsedEntry(
            timestamp=timestamp,
            level=level,
            message=data.get("message", ""),
            source=data.get("host") or data.get("program"),
            raw=raw or line,
            metadata=metadata,
        )
    
    def format(self, entry: ParsedEntry) -> str:
        """Format a ParsedEntry to syslog format."""
        month = entry.timestamp.strftime("%b") if entry.timestamp else "Jan"
        day = entry.timestamp.strftime("%d") if entry.timestamp else "01"
        time_str = entry.timestamp.strftime("%H:%M:%S") if entry.timestamp else "00:00:00"
        
        host = entry.metadata.get("host", "localhost")
        program = entry.metadata.get("program", "unknown")
        pid = entry.metadata.get("pid")
        
        pid_str = f"[{pid}]" if pid else ""
        
        if self.use_rfc3164:
            priority = self._level_to_priority(entry.level)
            return f"<{priority}>{month} {day} {time_str} {host} {program}{pid_str}: {entry.message}"
        
        return f"{month} {day} {time_str} {host} {program}{pid_str}: {entry.message}"
    
    def _parse_timestamp(self, month: str, day: str, time: str) -> Optional[datetime]:
        """Parse syslog timestamp."""
        try:
            year = datetime.now().year
            timestamp_str = f"{month} {day} {time}"
            return datetime.strptime(timestamp_str, "%b %d %H:%M:%S").replace(year=year)
        except ValueError:
            return None
    
    def _priority_to_level(self, priority: int) -> str:
        """Convert syslog priority to level."""
        severity = priority & 7
        mapping = {
            0: "EMERGENCY",
            1: "ALERT",
            2: "CRITICAL",
            3: "ERROR",
            4: "WARNING",
            5: "NOTICE",
            6: "INFO",
            7: "DEBUG",
        }
        return mapping.get(severity, "INFO")
    
    def _level_to_priority(self, level: Optional[str]) -> int:
        """Convert level to syslog priority."""
        if not level:
            return 13  # Default to syslog level 13 (Warning, facility user)
        
        level = level.upper()
        mapping = {
            "EMERGENCY": 0,
            "ALERT": 1,
            "CRITICAL": 2,
            "ERROR": 3,
            "WARNING": 4,
            "WARN": 4,
            "NOTICE": 5,
            "INFO": 6,
            "DEBUG": 7,
        }
        return mapping.get(level, 6) + 16  # Add facility (local0 = 16)
    
    def _extract_level_from_message(self, message: str) -> Optional[str]:
        """Try to extract log level from message content."""
        patterns = [
            (r'\bERROR\b', 'ERROR'),
            (r'\bWARN(?:ING)?\b', 'WARNING'),
            (r'\bINFO\b', 'INFO'),
            (r'\bDEBUG\b', 'DEBUG'),
            (r'\bCRITICAL\b', 'CRITICAL'),
            (r'\bFATAL\b', 'CRITICAL'),
        ]
        
        for pattern, level in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return level
        
        return None


def get_formatter(format: LogFormat) -> BaseFormatter:
    """Get appropriate formatter for log format."""
    formatters = {
        LogFormat.JSON: JSONFormatter(),
        LogFormat.APACHE_COMMON: ApacheFormatter(combined=False),
        LogFormat.APACHE_COMBINED: ApacheFormatter(combined=True),
        LogFormat.NGINX: NginxFormatter(),
        LogFormat.SYSLOG: SyslogFormatter(),
        LogFormat.CUSTOM: JSONFormatter(),  # Default for custom
    }
    
    return formatters.get(format, JSONFormatter())
