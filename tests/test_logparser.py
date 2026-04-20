"""
Unit Tests for LogParser

Tests cover:
- Parser initialization
- Line parsing (JSON, Apache, nginx, syslog)
- File parsing
- Stream parsing
- Error handling
"""

import pytest
import json
from datetime import datetime
from pathlib import Path
import tempfile
import os

from logparser import (
    LogParser, LogAnalyzer, LogAggregator, LogAlerter,
    LogFormat, ParsedEntry, ParseResult
)
from logparser.config import LogParserConfig


class TestLogParser:
    """Test cases for LogParser class."""
    
    def test_parser_initialization(self):
        """Test parser can be initialized with default settings."""
        parser = LogParser()
        assert parser is not None
        assert parser.format == LogFormat.AUTO
    
    def test_parser_with_format(self):
        """Test parser initialization with specific format."""
        parser = LogParser(format=LogFormat.JSON)
        assert parser.format == LogFormat.JSON
    
    def test_parse_json_line(self):
        """Test parsing JSON log lines."""
        parser = LogParser(format=LogFormat.JSON)
        
        log_line = json.dumps({
            "timestamp": "2024-01-15T10:30:00Z",
            "level": "INFO",
            "message": "Server started",
            "service": "api"
        })
        
        result = parser.parse_line(log_line)
        assert result is not None
        assert result.level == "INFO"
        assert result.message == "Server started"
    
    def test_parse_apache_common(self):
        """Test parsing Apache Common log format."""
        parser = LogParser(format=LogFormat.APACHE_COMMON)
        
        log_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
        
        result = parser.parse_line(log_line)
        assert result is not None
        assert result.metadata["status"] == 200
        assert result.metadata["method"] == "GET"
    
    def test_parse_apache_combined(self):
        """Test parsing Apache Combined log format."""
        parser = LogParser(format=LogFormat.APACHE_COMBINED)
        
        log_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08"'
        
        result = parser.parse_line(log_line)
        assert result is not None
        assert result.metadata["status"] == 200
        assert result.metadata["referrer"] == "http://www.example.com/start.html"
        assert result.metadata["user_agent"] == "Mozilla/4.08"
    
    def test_parse_nginx_access(self):
        """Test parsing nginx access log."""
        parser = LogParser(format=LogFormat.NGINX)
        
        log_line = '192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"'
        
        result = parser.parse_line(log_line)
        assert result is not None
        assert result.metadata["status"] == 200
        assert result.metadata["path"] == "/api/users"
    
    def test_parse_syslog(self):
        """Test parsing syslog format."""
        parser = LogParser(format=LogFormat.SYSLOG)
        
        log_line = 'Jan 15 10:30:00 server sshd[12345]: Accepted publickey for user'
        
        result = parser.parse_line(log_line)
        assert result is not None
        assert result.metadata["program"] == "sshd"
        assert "Accepted publickey" in result.message
    
    def test_parse_invalid_line(self):
        """Test handling of invalid log lines."""
        parser = LogParser(format=LogFormat.JSON)
        
        result = parser.parse_line("not valid json {")
        assert result is None
    
    def test_parse_empty_line(self):
        """Test handling of empty lines."""
        parser = LogParser()
        result = parser.parse_line("")
        assert result is None
    
    def test_parse_string(self):
        """Test parsing multi-line string."""
        parser = LogParser(format=LogFormat.JSON)
        
        content = json.dumps({"level": "INFO", "message": "Line 1"}) + "\n"
        content += json.dumps({"level": "ERROR", "message": "Line 2"})
        
        result = parser.parse_string(content)
        assert result.total_lines == 2
        assert result.parsed_lines == 2
    
    def test_parse_file(self):
        """Test parsing a log file."""
        parser = LogParser(format=LogFormat.JSON)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(json.dumps({"level": "INFO", "message": "Test 1"}) + "\n")
            f.write(json.dumps({"level": "ERROR", "message": "Test 2"}) + "\n")
            temp_path = f.name
        
        try:
            result = parser.parse_file(temp_path)
            assert result.total_lines == 2
            assert result.parsed_lines == 2
            assert result.success_rate == 100.0
        finally:
            os.unlink(temp_path)
    
    def test_parse_file_not_found(self):
        """Test error handling for missing files."""
        parser = LogParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/file.log")
    
    def test_parse_stream(self):
        """Test streaming parser."""
        parser = LogParser(format=LogFormat.JSON)
        
        entries = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(json.dumps({"level": "INFO", "message": "Test 1"}) + "\n")
            f.write(json.dumps({"level": "ERROR", "message": "Test 2"}) + "\n")
            temp_path = f.name
        
        try:
            result = parser.parse_stream(temp_path, lambda e: entries.append(e))
            assert len(entries) == 2
            assert result.total_lines == 2
        finally:
            os.unlink(temp_path)
    
    def test_parse_iterator(self):
        """Test iterator-based parsing."""
        parser = LogParser(format=LogFormat.JSON)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(json.dumps({"level": "INFO", "message": "Test 1"}) + "\n")
            f.write(json.dumps({"level": "ERROR", "message": "Test 2"}) + "\n")
            f.write(json.dumps({"level": "DEBUG", "message": "Test 3"}))
            temp_path = f.name
        
        try:
            entries = list(parser.parse_iter(temp_path))
            assert len(entries) == 3
        finally:
            os.unlink(temp_path)
    
    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        parser = LogParser(format=LogFormat.JSON)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(json.dumps({"level": "INFO", "message": "Test 1"}) + "\n")
            f.write("invalid line\n")  # This will fail
            f.write(json.dumps({"level": "ERROR", "message": "Test 2"}))
            temp_path = f.name
        
        try:
            result = parser.parse_file(temp_path)
            assert result.total_lines == 3
            assert result.parsed_lines == 2
            assert result.failed_lines == 1
            assert result.success_rate == pytest.approx(66.67, rel=0.1)
        finally:
            os.unlink(temp_path)


class TestLogAnalyzer:
    """Test cases for LogAnalyzer class."""
    
    @pytest.fixture
    def sample_entries(self):
        """Create sample log entries for testing."""
        return [
            ParsedEntry(
                timestamp=datetime(2024, 1, 15, 10, i),
                level="INFO",
                message="Request processed",
                source="api",
                raw="",
            )
            for i in range(10)
        ] + [
            ParsedEntry(
                timestamp=datetime(2024, 1, 15, 10, 15),
                level="ERROR",
                message="Connection failed",
                source="database",
                raw="",
            )
        ]
    
    def test_get_statistics(self, sample_entries):
        """Test statistics calculation."""
        analyzer = LogAnalyzer()
        stats = analyzer.get_statistics(sample_entries)
        
        assert stats.total_entries == 11
        assert stats.unique_messages == 2
        assert stats.entries_by_level["INFO"] == 10
        assert stats.entries_by_level["ERROR"] == 1
    
    def test_get_statistics_empty(self):
        """Test statistics with empty entries."""
        analyzer = LogAnalyzer()
        stats = analyzer.get_statistics([])
        
        assert stats.total_entries == 0
    
    def test_detect_anomalies(self, sample_entries):
        """Test anomaly detection."""
        analyzer = LogAnalyzer()
        anomalies = analyzer.detect_anomalies(sample_entries)
        
        assert isinstance(anomalies, list)
    
    def test_analyze_patterns(self, sample_entries):
        """Test pattern analysis."""
        analyzer = LogAnalyzer()
        patterns = analyzer.analyze_patterns(sample_entries)
        
        assert "frequent_messages" in patterns
        assert "level_distribution" in patterns
        assert len(patterns["frequent_messages"]) > 0


class TestLogAggregator:
    """Test cases for LogAggregator class."""
    
    @pytest.fixture
    def sample_entries(self):
        """Create sample log entries for testing."""
        entries = []
        for hour in range(24):
            for minute in range(5):
                entries.append(ParsedEntry(
                    timestamp=datetime(2024, 1, 15, hour, minute),
                    level="INFO" if hour < 12 else "ERROR",
                    message=f"Message {hour}",
                    source="service-a" if hour < 12 else "service-b",
                    raw="",
                    metadata={"response_time": hour * 10 + minute}
                ))
        return entries
    
    def test_aggregate_by_field(self, sample_entries):
        """Test aggregation by field."""
        aggregator = LogAggregator()
        result = aggregator.aggregate_by_field(
            sample_entries,
            field="level",
            metric="count"
        )
        
        assert result.total_groups == 2
        assert "INFO" in result.groups
        assert "ERROR" in result.groups
    
    def test_aggregate_by_time(self, sample_entries):
        """Test time-based aggregation."""
        aggregator = LogAggregator()
        result = aggregator.aggregate_by_time(
            sample_entries,
            interval="hour"
        )
        
        assert result.total_groups == 24
    
    def test_top_n(self, sample_entries):
        """Test top N aggregation."""
        aggregator = LogAggregator()
        metrics = aggregator.top_n(sample_entries, field="source", n=5)
        
        assert len(metrics) <= 5
        assert all(m.count > 0 for m in metrics)


class TestLogAlerter:
    """Test cases for LogAlerter class."""
    
    @pytest.fixture
    def sample_entries(self):
        """Create sample log entries for testing."""
        return [
            ParsedEntry(
                timestamp=datetime(2024, 1, 15, 10, i),
                level="ERROR",
                message="Error occurred",
                source="api",
                raw="",
            )
            for i in range(5)
        ]
    
    def test_add_rule(self):
        """Test adding alert rules."""
        alerter = LogAlerter()
        alerter.add_rule(
            name="test_rule",
            condition="level == 'ERROR'",
            severity="ERROR"
        )
        
        assert len(alerter.rules) == 1
        assert alerter.rules[0].name == "test_rule"
    
    def test_process_entries(self, sample_entries):
        """Test alert processing."""
        alerter = LogAlerter()
        alerter.add_rule(
            name="high_error_rate",
            condition="level == 'ERROR'",
            severity="ERROR",
            match_count=3
        )
        
        events = alerter.process_entries(sample_entries)
        
        assert events.total_triggered >= 0
    
    def test_cooldown(self, sample_entries):
        """Test alert cooldown mechanism."""
        alerter = LogAlerter()
        alerter.add_rule(
            name="error_rule",
            condition="level == 'ERROR'",
            severity="ERROR",
            cooldown_seconds=60
        )
        
        events1 = alerter.process_entries(sample_entries)
        events2 = alerter.process_entries(sample_entries)
        
        # Second run should be suppressed by cooldown
        assert events2.total_triggered == 0


class TestConfig:
    """Test cases for configuration."""
    
    def test_config_default(self):
        """Test default configuration."""
        config = LogParserConfig()
        assert config.encoding == "utf-8"
        assert config.chunk_size == 1000
    
    def test_config_to_dict(self):
        """Test config serialization."""
        config = LogParserConfig()
        data = config.to_dict()
        
        assert isinstance(data, dict)
        assert "encoding" in data
    
    def test_config_from_dict(self):
        """Test config deserialization."""
        data = {"encoding": "latin-1", "chunk_size": 5000}
        config = LogParserConfig.from_dict(data)
        
        assert config.encoding == "latin-1"
        assert config.chunk_size == 5000
    
    def test_config_json(self):
        """Test JSON serialization."""
        config = LogParserConfig(encoding="utf-16")
        json_str = config.to_json()
        
        loaded = LogParserConfig.from_json(json_str)
        assert loaded.encoding == "utf-16"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
