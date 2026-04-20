#!/usr/bin/env python3
"""
Basic Usage Examples for LogParser

This script demonstrates common use cases for the LogParser library.
"""

import json
from datetime import datetime
from logparser import (
    LogParser, LogAnalyzer, LogAggregator, LogAlerter,
    LogFormat, ParsedEntry
)


def example_json_parsing():
    """Example: Parse JSON formatted logs."""
    print("=" * 60)
    print("Example: JSON Log Parsing")
    print("=" * 60)
    
    # Sample JSON log lines
    log_lines = [
        json.dumps({
            "timestamp": "2024-01-15T10:30:00Z",
            "level": "INFO",
            "message": "Server started successfully",
            "service": "api-gateway",
            "port": 8080
        }),
        json.dumps({
            "timestamp": "2024-01-15T10:30:01Z",
            "level": "WARNING",
            "message": "High memory usage detected",
            "service": "api-gateway",
            "memory_percent": 85.5
        }),
        json.dumps({
            "timestamp": "2024-01-15T10:30:02Z",
            "level": "ERROR",
            "message": "Connection timeout to database",
            "service": "api-gateway",
            "database": "primary",
            "timeout_ms": 5000
        }),
    ]
    
    # Initialize parser
    parser = LogParser(format=LogFormat.JSON)
    
    # Parse lines
    for line in log_lines:
        entry = parser.parse_line(line)
        if entry:
            print(f"[{entry.level}] {entry.timestamp}: {entry.message}")
            print(f"  Source: {entry.source}")
            print(f"  Metadata: {entry.metadata}")
            print()


def example_apache_parsing():
    """Example: Parse Apache access logs."""
    print("=" * 60)
    print("Example: Apache Log Parsing")
    print("=" * 60)
    
    # Sample Apache Combined log format
    log_lines = [
        '192.168.1.100 - - [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"',
        '192.168.1.101 - - [15/Jan/2024:10:30:01 +0000] "POST /api/login HTTP/1.1" 401 256 "https://example.com/login" "Mozilla/5.0"',
        '192.168.1.102 - - [15/Jan/2024:10:30:02 +0000] "GET /api/products HTTP/1.1" 500 512 "https://example.com" "Mozilla/5.0"',
    ]
    
    # Initialize parser for Apache Combined format
    parser = LogParser(format=LogFormat.APACHE_COMBINED)
    
    for line in log_lines:
        entry = parser.parse_line(line)
        if entry:
            print(f"[{entry.metadata.get('status')}] {entry.message}")
            print(f"  Method: {entry.metadata.get('method')}")
            print(f"  Path: {entry.metadata.get('path')}")
            print(f"  Referrer: {entry.metadata.get('referrer')}")
            print(f"  User Agent: {entry.metadata.get('user_agent')}")
            print()


def example_analysis():
    """Example: Analyze parsed logs."""
    print("=" * 60)
    print("Example: Log Analysis")
    print("=" * 60)
    
    # Create sample entries
    entries = []
    for i in range(100):
        entries.append(ParsedEntry(
            timestamp=datetime(2024, 1, 15, 10, i % 60),
            level="INFO" if i % 10 != 0 else "ERROR",
            message=f"Request {i} processed" if i % 10 != 0 else f"Request {i} failed",
            source="api" if i % 2 == 0 else "worker",
            raw="",
            metadata={"request_id": f"req-{i:04d}"}
        ))
    
    # Analyze
    analyzer = LogAnalyzer()
    stats = analyzer.get_statistics(entries)
    
    print("Statistics:")
    print(f"  Total Entries: {stats.total_entries}")
    print(f"  Unique Messages: {stats.unique_messages}")
    print(f"  Error Rate: {stats.error_rate:.2f}%")
    print()
    
    print("Level Distribution:")
    for level, count in stats.entries_by_level.items():
        print(f"  {level}: {count}")
    print()
    
    print("Source Distribution:")
    for source, count in stats.entries_by_source.items():
        print(f"  {source}: {count}")
    print()
    
    # Generate report
    report = analyzer.generate_report(entries)
    print("Report:")
    print(report)


def example_aggregation():
    """Example: Aggregate log data."""
    print("=" * 60)
    print("Example: Log Aggregation")
    print("=" * 60)
    
    # Create sample entries
    entries = []
    for hour in range(24):
        for _ in range(10):
            entries.append(ParsedEntry(
                timestamp=datetime(2024, 1, 15, hour, 30),
                level="INFO" if hour < 12 else "WARNING",
                message=f"Request processed",
                source="service-a" if hour % 2 == 0 else "service-b",
                raw="",
                metadata={"response_time": hour * 10}
            ))
    
    aggregator = LogAggregator()
    
    # Aggregate by level
    print("By Level:")
    result = aggregator.aggregate_by_field(entries, field="level", metric="count")
    for group, metrics in result.groups.items():
        print(f"  {group}: {metrics[0].count}")
    print()
    
    # Aggregate by time
    print("By Hour:")
    result = aggregator.aggregate_by_time(entries, interval="hour")
    for group, metrics in sorted(result.groups.items())[:5]:
        print(f"  {group}: {metrics[0].count}")
    print("  ...")
    print()
    
    # Top sources
    print("Top Sources:")
    top_sources = aggregator.top_n(entries, field="source", n=5)
    for metric in top_sources:
        print(f"  {metric.group_by['source']}: {metric.count}")


def example_alerting():
    """Example: Set up alerting rules."""
    print("=" * 60)
    print("Example: Alerting")
    print("=" * 60)
    
    # Create sample entries with errors
    entries = []
    for i in range(50):
        entries.append(ParsedEntry(
            timestamp=datetime(2024, 1, 15, 10, i % 60),
            level="ERROR" if i < 5 else "INFO",
            message="Connection timeout" if i < 5 else "Request processed",
            source="api",
            raw="",
        ))
    
    # Set up alerter
    alerter = LogAlerter()
    
    # Add rules
    alerter.add_rule(
        name="error_threshold",
        condition="level == 'ERROR'",
        severity="ERROR",
        match_count=3,
        cooldown_seconds=60
    )
    
    alerter.add_rule(
        name="high_volume",
        condition="message contains 'timeout'",
        severity="WARNING",
        match_count=2
    )
    
    # Process entries
    events = alerter.process_entries(entries)
    
    print(f"Alerts Triggered: {events.total_triggered}")
    print(f"Alerts Resolved: {events.total_resolved}")
    print(f"Processing Time: {events.processing_time:.4f}s")
    print()
    
    for alert in events.alerts:
        print(f"[{alert.severity.value.upper()}] {alert.message}")
        print(f"  Rule: {alert.rule.name}")
        print(f"  Count: {alert.count}")
        print()
    
    # Show active alerts
    active = alerter.get_active_alerts()
    print(f"Active Alerts: {len(active)}")


def example_pattern_matching():
    """Example: Use pattern matching."""
    print("=" * 60)
    print("Example: Pattern Matching")
    print("=" * 60)
    
    from logparser.patterns import PatternMatcher, create_common_patterns, PatternRegistry
    
    # Create registry and add common patterns
    registry = PatternRegistry()
    create_common_patterns(registry)
    
    # Create matcher
    matcher = PatternMatcher(registry)
    
    # Test patterns
    test_strings = [
        "2024-01-15T10:30:00Z Server started on port 8080",
        "192.168.1.100 connected from 10.0.0.1",
        "ERROR: Failed to connect to database at db.example.com",
        "GET /api/users?id=123 HTTP/1.1",
    ]
    
    for text in test_strings:
        print(f"Input: {text}")
        
        # Match all patterns
        results = matcher.match_all(text)
        if results:
            for result in results:
                print(f"  -> {result.pattern_name}: {result.groups}")
        else:
            print("  -> No patterns matched")
        print()


if __name__ == "__main__":
    example_json_parsing()
    print("\n")
    example_apache_parsing()
    print("\n")
    example_analysis()
    print("\n")
    example_aggregation()
    print("\n")
    example_alerting()
    print("\n")
    example_pattern_matching()
