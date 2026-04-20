"""
Log Analyzer Module

Provides analysis capabilities for parsed log entries including
pattern analysis, statistics, and anomaly detection.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from enum import Enum
import statistics

from .parser import ParsedEntry, ParseResult


class AnomalyType(Enum):
    """Types of anomalies that can be detected."""
    VOLUME_SPIKE = "volume_spike"
    ERROR_RATE = "error_rate"
    LATENCY_INCREASE = "latency_increase"
    PATTERN_BREAK = "pattern_break"
    UNUSUAL_SOURCE = "unusual_source"


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    type: AnomalyType
    severity: str  # low, medium, high, critical
    description: str
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    affected_count: int = 0


@dataclass
class LogStatistics:
    """Statistical summary of log data."""
    total_entries: int = 0
    entries_by_level: Dict[str, int] = field(default_factory=dict)
    entries_by_source: Dict[str, int] = field(default_factory=dict)
    unique_messages: int = 0
    time_range: Tuple[Optional[datetime], Optional[datetime]] = (None, None)
    hourly_distribution: Dict[int, int] = field(default_factory=dict)
    
    # Additional statistics
    avg_entries_per_hour: float = 0.0
    error_rate: float = 0.0
    most_common_messages: List[Tuple[str, int]] = field(default_factory=list)


class LogAnalyzer:
    """
    Analyzer for parsed log entries.
    
    Provides:
    - Statistical analysis (counts, distributions, trends)
    - Pattern analysis (frequent items, rare events)
    - Anomaly detection (spikes, errors, unusual patterns)
    - Time series analysis
    
    Example:
        >>> analyzer = LogAnalyzer()
        >>> stats = analyzer.get_statistics(parse_result.entries)
        >>> anomalies = analyzer.detect_anomalies(parse_result.entries)
    """
    
    def __init__(self, sensitivity: float = 1.5):
        """
        Initialize the analyzer.
        
        Args:
            sensitivity: Detection sensitivity (higher = more sensitive)
        """
        self.sensitivity = sensitivity
    
    def get_statistics(self, entries: List[ParsedEntry]) -> LogStatistics:
        """
        Calculate comprehensive statistics for log entries.
        
        Args:
            entries: List of parsed log entries
            
        Returns:
            LogStatistics with calculated metrics
        """
        if not entries:
            return LogStatistics()
        
        stats = LogStatistics()
        stats.total_entries = len(entries)
        
        # Count by level
        stats.entries_by_level = Counter(
            e.level for e in entries if e.level
        )
        
        # Count by source
        stats.entries_by_source = Counter(
            e.source for e in entries if e.source
        )
        
        # Unique messages
        stats.unique_messages = len(set(e.message for e in entries))
        
        # Time range
        timestamps = [e.timestamp for e in entries if e.timestamp]
        if timestamps:
            stats.time_range = (min(timestamps), max(timestamps))
            
            # Hourly distribution
            for ts in timestamps:
                stats.hourly_distribution[ts.hour] = \
                    stats.hourly_distribution.get(ts.hour, 0) + 1
        
        # Calculate averages
        if stats.time_range[0] and stats.time_range[1]:
            duration = stats.time_range[1] - stats.time_range[0]
            hours = max(duration.total_seconds() / 3600, 1)
            stats.avg_entries_per_hour = stats.total_entries / hours
        
        # Error rate
        error_count = stats.entries_by_level.get("ERROR", 0) + \
                      stats.entries_by_level.get("error", 0) + \
                      stats.entries_by_level.get("CRITICAL", 0) + \
                      stats.entries_by_level.get("WARN", 0) + \
                      stats.entries_by_level.get("warn", 0)
        stats.error_rate = (error_count / stats.total_entries * 100) if stats.total_entries else 0
        
        # Most common messages
        message_counts = Counter(e.message for e in entries)
        stats.most_common_messages = message_counts.most_common(10)
        
        return stats
    
    def detect_anomalies(
        self,
        entries: List[ParsedEntry],
        time_window: int = 60,
    ) -> List[Anomaly]:
        """
        Detect anomalies in log entries.
        
        Args:
            entries: List of parsed log entries
            time_window: Time window in minutes for analysis
            
        Returns:
            List of detected anomalies
        """
        anomalies: List[Anomaly] = []
        
        if not entries:
            return anomalies
        
        timestamps = sorted([e.timestamp for e in entries if e.timestamp])
        if len(timestamps) < 2:
            return anomalies
        
        # Volume spike detection
        volume_anomalies = self._detect_volume_spikes(entries, timestamps)
        anomalies.extend(volume_anomalies)
        
        # Error rate anomalies
        error_anomalies = self._detect_error_rate_anomalies(entries, timestamps)
        anomalies.extend(error_anomalies)
        
        # Unusual sources
        source_anomalies = self._detect_unusual_sources(entries)
        anomalies.extend(source_anomalies)
        
        return anomalies
    
    def _detect_volume_spikes(
        self,
        entries: List[ParsedEntry],
        timestamps: List[datetime],
    ) -> List[Anomaly]:
        """Detect volume spikes in log entries."""
        anomalies: List[Anomaly] = []
        
        if len(timestamps) < 10:
            return anomalies
        
        # Group by minute
        minute_counts: Dict[int, int] = defaultdict(int)
        for ts in timestamps:
            minute_counts[ts.minute] += 1
        
        values = list(minute_counts.values())
        if len(values) < 3:
            return anomalies
        
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0
        
        threshold = mean + (self.sensitivity * std)
        
        for minute, count in minute_counts.items():
            if count > threshold:
                anomalies.append(Anomaly(
                    type=AnomalyType.VOLUME_SPIKE,
                    severity="high" if count > threshold * 2 else "medium",
                    description=f"Volume spike detected: {count} entries in minute {minute}",
                    timestamp=timestamps[0],
                    details={"minute": minute, "count": count, "threshold": threshold},
                    affected_count=count,
                ))
        
        return anomalies
    
    def _detect_error_rate_anomalies(
        self,
        entries: List[ParsedEntry],
        timestamps: List[datetime],
    ) -> List[Anomaly]:
        """Detect unusual error rates."""
        anomalies: List[Anomaly] = []
        
        error_entries = [e for e in entries if e.level in ("ERROR", "error", "CRITICAL")]
        if not error_entries:
            return anomalies
        
        error_rate = len(error_entries) / len(entries) * 100
        
        if error_rate > 10:
            severity = "critical" if error_rate > 50 else "high" if error_rate > 25 else "medium"
            anomalies.append(Anomaly(
                type=AnomalyType.ERROR_RATE,
                severity=severity,
                description=f"High error rate: {error_rate:.1f}%",
                timestamp=error_entries[0].timestamp if error_entries else timestamps[0],
                details={"error_rate": error_rate, "total_errors": len(error_entries)},
                affected_count=len(error_entries),
            ))
        
        return anomalies
    
    def _detect_unusual_sources(self, entries: List[ParsedEntry]) -> List[Anomaly]:
        """Detect unusual or rare sources."""
        anomalies: List[Anomaly] = []
        
        source_counts = Counter(e.source for e in entries if e.source)
        if not source_counts:
            return anomalies
        
        # Find rare sources (less than 1% of total)
        threshold = len(entries) * 0.01
        
        for source, count in source_counts.items():
            if count < threshold and count >= 1:
                anomalies.append(Anomaly(
                    type=AnomalyType.UNUSUAL_SOURCE,
                    severity="low",
                    description=f"Unusual source detected: {source} (count: {count})",
                    timestamp=datetime.now(),
                    details={"source": source, "count": count},
                    affected_count=count,
                ))
        
        return anomalies
    
    def analyze_patterns(self, entries: List[ParsedEntry]) -> Dict[str, Any]:
        """
        Analyze patterns in log entries.
        
        Args:
            entries: List of parsed log entries
            
        Returns:
            Dictionary with pattern analysis results
        """
        patterns: Dict[str, Any] = {
            "frequent_messages": [],
            "rare_messages": [],
            "level_distribution": {},
            "source_distribution": {},
            "hourly_patterns": {},
        }
        
        if not entries:
            return patterns
        
        # Message frequency
        message_counts = Counter(e.message for e in entries)
        total = len(entries)
        
        patterns["frequent_messages"] = [
            {"message": msg, "count": count, "percentage": count/total*100}
            for msg, count in message_counts.most_common(20)
        ]
        
        patterns["rare_messages"] = [
            {"message": msg, "count": count}
            for msg, count in message_counts.most_common()[-10:]
        ]
        
        # Level distribution
        patterns["level_distribution"] = dict(
            Counter(e.level for e in entries if e.level)
        )
        
        # Source distribution
        patterns["source_distribution"] = dict(
            Counter(e.source for e in entries if e.source)
        )
        
        # Hourly patterns
        hourly = defaultdict(int)
        for e in entries:
            if e.timestamp:
                hourly[e.timestamp.hour] += 1
        patterns["hourly_patterns"] = dict(hourly)
        
        return patterns
    
    def generate_report(self, entries: List[ParsedEntry]) -> str:
        """
        Generate a comprehensive text report.
        
        Args:
            entries: List of parsed log entries
            
        Returns:
            Formatted report string
        """
        stats = self.get_statistics(entries)
        patterns = self.analyze_patterns(entries)
        anomalies = self.detect_anomalies(entries)
        
        lines = [
            "=" * 60,
            "LOG ANALYSIS REPORT",
            "=" * 60,
            "",
            "OVERVIEW",
            "-" * 40,
            f"Total Entries:     {stats.total_entries:,}",
            f"Unique Messages:  {stats.unique_messages:,}",
            f"Error Rate:        {stats.error_rate:.2f}%",
            f"Entries/Hour:      {stats.avg_entries_per_hour:.1f}",
            "",
            "TIME RANGE",
            "-" * 40,
        ]
        
        if stats.time_range[0] and stats.time_range[1]:
            lines.append(f"Start: {stats.time_range[0].isoformat()}")
            lines.append(f"End:   {stats.time_range[1].isoformat()}")
        else:
            lines.append("Unknown")
        
        lines.extend([
            "",
            "LEVEL DISTRIBUTION",
            "-" * 40,
        ])
        for level, count in sorted(stats.entries_by_level.items()):
            pct = count / stats.total_entries * 100
            lines.append(f"  {level:10s}: {count:6,} ({pct:5.1f}%)")
        
        lines.extend([
            "",
            "TOP SOURCES",
            "-" * 40,
        ])
        top_sources = sorted(
            stats.entries_by_source.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        for source, count in top_sources:
            lines.append(f"  {source[:40]:40s}: {count:,}")
        
        if patterns["hourly_patterns"]:
            lines.extend([
                "",
                "HOURLY DISTRIBUTION",
                "-" * 40,
            ])
            for hour in range(24):
                count = patterns["hourly_patterns"].get(hour, 0)
                bar = "█" * (count // max(1, stats.total_entries // 100))
                lines.append(f"  {hour:02d}:00  {count:5,} {bar}")
        
        if anomalies:
            lines.extend([
                "",
                f"ANOMALIES DETECTED: {len(anomalies)}",
                "-" * 40,
            ])
            for anomaly in anomalies:
                lines.append(f"  [{anomaly.severity.upper():8s}] {anomaly.description}")
        
        lines.extend([
            "",
            "=" * 60,
        ])
        
        return "\n".join(lines)
