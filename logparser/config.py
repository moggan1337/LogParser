"""
Configuration Module

Provides configuration management for LogParser with
support for various settings and options.
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import timedelta
import json
import os


@dataclass
class LogParserConfig:
    """
    Configuration for LogParser.
    
    Provides settings for:
    - Parsing behavior
    - Performance tuning
    - Error handling
    - Output formatting
    """
    
    # Encoding settings
    encoding: str = "utf-8"
    encoding_errors: str = "replace"  # replace, ignore, strict
    
    # Performance settings
    chunk_size: int = 1000
    max_line_length: int = 65536
    buffer_size: int = 8192
    
    # Parsing behavior
    strict_mode: bool = False
    skip_invalid_lines: bool = True
    skip_empty_lines: bool = True
    auto_detect_format: bool = True
    max_sample_lines: int = 100
    
    # Timestamp settings
    default_timezone: str = "UTC"
    timestamp_formats: List[str] = field(default_factory=lambda: [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    ])
    
    # Field mapping (JSON logs)
    field_mapping: Dict[str, str] = field(default_factory=dict)
    
    # Output settings
    include_raw: bool = True
    include_metadata: bool = True
    datetime_format: str = "iso"  # iso, unix, custom
    
    # Error handling
    on_parse_error: str = "skip"  # skip, log, raise
    on_format_error: str = "skip"
    max_errors: int = 1000
    error_log_file: Optional[str] = None
    
    # Filtering
    filter_levels: Optional[List[str]] = None
    filter_sources: Optional[List[str]] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    
    # Aggregation settings
    aggregation_window: str = "hour"  # minute, hour, day
    aggregation_fields: List[str] = field(default_factory=lambda: ["level", "source"])
    
    # Alerting settings
    alert_cooldown: int = 300  # seconds
    alert_severity_threshold: str = "WARNING"
    alert_channels: List[str] = field(default_factory=list)
    
    # Performance monitoring
    track_performance: bool = True
    log_slow_operations: bool = False
    slow_operation_threshold: float = 1.0  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "encoding": self.encoding,
            "encoding_errors": self.encoding_errors,
            "chunk_size": self.chunk_size,
            "max_line_length": self.max_line_length,
            "buffer_size": self.buffer_size,
            "strict_mode": self.strict_mode,
            "skip_invalid_lines": self.skip_invalid_lines,
            "skip_empty_lines": self.skip_empty_lines,
            "auto_detect_format": self.auto_detect_format,
            "max_sample_lines": self.max_sample_lines,
            "default_timezone": self.default_timezone,
            "timestamp_formats": self.timestamp_formats,
            "field_mapping": self.field_mapping,
            "include_raw": self.include_raw,
            "include_metadata": self.include_metadata,
            "datetime_format": self.datetime_format,
            "on_parse_error": self.on_parse_error,
            "on_format_error": self.on_format_error,
            "max_errors": self.max_errors,
            "error_log_file": self.error_log_file,
            "filter_levels": self.filter_levels,
            "filter_sources": self.filter_sources,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "aggregation_window": self.aggregation_window,
            "aggregation_fields": self.aggregation_fields,
            "alert_cooldown": self.alert_cooldown,
            "alert_severity_threshold": self.alert_severity_threshold,
            "alert_channels": self.alert_channels,
            "track_performance": self.track_performance,
            "log_slow_operations": self.log_slow_operations,
            "slow_operation_threshold": self.slow_operation_threshold,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogParserConfig":
        """Create config from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
    
    def to_json(self) -> str:
        """Export config to JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> "LogParserConfig":
        """Load config from JSON."""
        return cls.from_dict(json.loads(json_str))
    
    def to_file(self, path: str) -> None:
        """Save config to file."""
        with open(path, "w") as f:
            f.write(self.to_json())
    
    @classmethod
    def from_file(cls, path: str) -> "LogParserConfig":
        """Load config from file."""
        with open(path, "r") as f:
            return cls.from_json(f.read())
    
    @classmethod
    def from_env(cls, prefix: str = "LOGPARSER_") -> "LogParserConfig":
        """
        Load config from environment variables.
        
        Environment variables should be uppercase with underscores.
        Example: LOGPARSER_CHUNK_SIZE -> chunk_size
        """
        data = {}
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                
                # Type conversion
                if value.lower() in ("true", "false"):
                    value = value.lower() == "true"
                elif value.isdigit():
                    value = int(value)
                elif "," in value:
                    value = [v.strip() for v in value.split(",")]
                
                data[config_key] = value
        
        return cls.from_dict(data)
    
    def merge(self, other: "LogParserConfig") -> "LogParserConfig":
        """Merge with another config (other takes precedence)."""
        merged = self.to_dict()
        other_dict = other.to_dict()
        
        for key, value in other_dict.items():
            if value is not None and value != getattr(self, key):
                merged[key] = value
        
        return self.__class__.from_dict(merged)


# Predefined configurations for common use cases
PRESETS = {
    "default": LogParserConfig(),
    
    "performance": LogParserConfig(
        chunk_size=5000,
        buffer_size=65536,
        skip_invalid_lines=True,
        track_performance=True,
        log_slow_operations=True,
    ),
    
    "strict": LogParserConfig(
        strict_mode=True,
        skip_invalid_lines=False,
        on_parse_error="raise",
        on_format_error="raise",
    ),
    
    "debugging": LogParserConfig(
        track_performance=True,
        log_slow_operations=True,
        slow_operation_threshold=0.1,
        include_raw=True,
        include_metadata=True,
    ),
    
    "production": LogParserConfig(
        chunk_size=2000,
        skip_invalid_lines=True,
        track_performance=True,
        log_slow_operations=True,
        slow_operation_threshold=2.0,
        alert_cooldown=600,
    ),
}


def get_preset(name: str) -> LogParserConfig:
    """Get a preset configuration."""
    if name not in PRESETS:
        raise ValueError(f"Unknown preset: {name}. Available: {list(PRESETS.keys())}")
    return PRESETS[name]


def create_custom_preset(name: str, **kwargs) -> LogParserConfig:
    """Create and register a custom preset."""
    config = LogParserConfig(**kwargs)
    PRESETS[name] = config
    return config
