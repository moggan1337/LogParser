"""
Log Aggregator Module

Provides aggregation capabilities for log data including
counting, grouping, time-based aggregation, and metrics.
"""

from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from enum import Enum
import json

from .parser import ParsedEntry, ParseResult


class AggregationType(Enum):
    """Types of aggregation operations."""
    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    PERCENTILE = "percentile"
    RATE = "rate"


@dataclass
class AggregatedMetric:
    """Represents an aggregated metric."""
    name: str
    value: Any
    count: int = 0
    timestamp: Optional[datetime] = None
    group_by: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregationResult:
    """Container for aggregation results."""
    metrics: List[AggregatedMetric] = field(default_factory=list)
    groups: Dict[str, List[AggregatedMetric]] = field(default_factory=dict)
    total_groups: int = 0
    aggregation_time: float = 0.0


class LogAggregator:
    """
    Aggregator for log entries.
    
    Provides:
    - Group by operations (source, level, time)
    - Count aggregations
    - Numeric field aggregations (sum, avg, min, max)
    - Time-based aggregation (per minute, hour, day)
    - Custom aggregation functions
    
    Example:
        >>> aggregator = LogAggregator()
        >>> result = aggregator.aggregate_by_field(
        ...     entries,
        ...     field="source",
        ...     metric="count"
        ... )
    """
    
    def __init__(self):
        """Initialize the aggregator."""
        pass
    
    def aggregate_by_field(
        self,
        entries: List[ParsedEntry],
        field: str,
        metric: AggregationType = AggregationType.COUNT,
        value_field: Optional[str] = None,
    ) -> AggregationResult:
        """
        Aggregate entries by a specific field.
        
        Args:
            entries: List of parsed log entries
            field: Field to group by
            metric: Aggregation metric to calculate
            value_field: Field to aggregate (for sum/avg/min/max)
            
        Returns:
            AggregationResult with grouped metrics
        """
        import time
        start_time = time.time()
        
        result = AggregationResult()
        groups: Dict[str, List[ParsedEntry]] = defaultdict(list)
        
        # Group entries by field
        for entry in entries:
            value = self._get_field_value(entry, field)
            if value is not None:
                groups[str(value)].append(entry)
        
        # Calculate metrics for each group
        for group_name, group_entries in groups.items():
            metric_value = self._calculate_metric(
                group_entries, metric, value_field
            )
            
            result.groups[group_name].append(AggregatedMetric(
                name=field,
                value=metric_value,
                count=len(group_entries),
                group_by={field: group_name},
            ))
        
        result.total_groups = len(groups)
        result.aggregation_time = time.time() - start_time
        return result
    
    def aggregate_by_time(
        self,
        entries: List[ParsedEntry],
        interval: str = "hour",
        metric: AggregationType = AggregationType.COUNT,
        value_field: Optional[str] = None,
    ) -> AggregationResult:
        """
        Aggregate entries by time interval.
        
        Args:
            entries: List of parsed log entries
            interval: Time interval (minute, hour, day)
            metric: Aggregation metric to calculate
            value_field: Field to aggregate
            
        Returns:
            AggregationResult with time-bucketed metrics
        """
        import time
        start_time = time.time()
        
        result = AggregationResult()
        time_buckets: Dict[str, List[ParsedEntry]] = defaultdict(list)
        
        for entry in entries:
            if not entry.timestamp:
                continue
            
            bucket_key = self._get_time_bucket(entry.timestamp, interval)
            time_buckets[bucket_key].append(entry)
        
        for bucket_name in sorted(time_buckets.keys()):
            bucket_entries = time_buckets[bucket_name]
            metric_value = self._calculate_metric(
                bucket_entries, metric, value_field
            )
            
            result.groups[bucket_name].append(AggregatedMetric(
                name=f"{metric.value}_per_{interval}",
                value=metric_value,
                count=len(bucket_entries),
                timestamp=datetime.fromisoformat(bucket_name) if bucket_name else None,
            ))
        
        result.total_groups = len(time_buckets)
        result.aggregation_time = time.time() - start_time
        return result
    
    def aggregate_by_multiple_fields(
        self,
        entries: List[ParsedEntry],
        fields: List[str],
        metric: AggregationType = AggregationType.COUNT,
        value_field: Optional[str] = None,
    ) -> AggregationResult:
        """
        Aggregate entries by multiple fields.
        
        Args:
            entries: List of parsed log entries
            fields: List of fields to group by
            metric: Aggregation metric to calculate
            value_field: Field to aggregate
            
        Returns:
            AggregationResult with multi-dimensional metrics
        """
        import time
        start_time = time.time()
        
        result = AggregationResult()
        groups: Dict[Tuple, List[ParsedEntry]] = defaultdict(list)
        
        for entry in entries:
            key = tuple(self._get_field_value(entry, f) for f in fields)
            groups[key].append(entry)
        
        for group_key, group_entries in groups.items():
            metric_value = self._calculate_metric(
                group_entries, metric, value_field
            )
            
            group_by_dict = dict(zip(fields, group_key))
            
            result.groups[str(group_key)].append(AggregatedMetric(
                name="_".join(fields),
                value=metric_value,
                count=len(group_entries),
                group_by=group_by_dict,
            ))
        
        result.total_groups = len(groups)
        result.aggregation_time = time.time() - start_time
        return result
    
    def calculate_rate(
        self,
        entries: List[ParsedEntry],
        field: str,
        window_minutes: int = 5,
    ) -> List[AggregatedMetric]:
        """
        Calculate rate of occurrence per time window.
        
        Args:
            entries: List of parsed log entries
            field: Field to track
            window_minutes: Time window in minutes
            
        Returns:
            List of rate metrics per window
        """
        if not entries:
            return []
        
        # Sort by timestamp
        sorted_entries = sorted(
            [e for e in entries if e.timestamp],
            key=lambda x: x.timestamp
        )
        
        if not sorted_entries:
            return []
        
        metrics: List[AggregatedMetric] = []
        start_time = sorted_entries[0].timestamp
        end_time = sorted_entries[-1].timestamp
        
        current_time = start_time
        while current_time <= end_time:
            window_end = current_time + timedelta(minutes=window_minutes)
            
            window_entries = [
                e for e in sorted_entries
                if current_time <= e.timestamp < window_end
            ]
            
            count = sum(
                1 for e in window_entries
                if self._get_field_value(e, field)
            )
            
            metrics.append(AggregatedMetric(
                name=f"rate_{field}",
                value=count / window_minutes,
                count=count,
                timestamp=current_time,
            ))
            
            current_time = window_end
        
        return metrics
    
    def top_n(
        self,
        entries: List[ParsedEntry],
        field: str,
        n: int = 10,
        metric: AggregationType = AggregationType.COUNT,
    ) -> List[AggregatedMetric]:
        """
        Get top N values for a field.
        
        Args:
            entries: List of parsed log entries
            field: Field to analyze
            n: Number of top items to return
            metric: Aggregation metric
            
        Returns:
            List of top N metrics
        """
        counter: Counter = Counter()
        
        for entry in entries:
            value = self._get_field_value(entry, field)
            if value is not None:
                counter[str(value)] += 1
        
        metrics = []
        for item, count in counter.most_common(n):
            metrics.append(AggregatedMetric(
                name=field,
                value=count,
                count=count,
                group_by={field: item},
            ))
        
        return metrics
    
    def percentiles(
        self,
        entries: List[ParsedEntry],
        field: str,
        percentiles: List[int] = [50, 90, 95, 99],
    ) -> List[AggregatedMetric]:
        """
        Calculate percentiles for a numeric field.
        
        Args:
            entries: List of parsed log entries
            field: Numeric field to analyze
            percentiles: List of percentile values to calculate
            
        Returns:
            List of percentile metrics
        """
        values = []
        for entry in entries:
            value = self._get_field_value(entry, field)
            if value is not None and isinstance(value, (int, float)):
                values.append(float(value))
        
        if not values:
            return []
        
        values.sort()
        metrics = []
        
        for p in percentiles:
            index = int(len(values) * p / 100)
            index = min(index, len(values) - 1)
            
            metrics.append(AggregatedMetric(
                name=f"p{p}_{field}",
                value=values[index],
                count=len(values),
                metadata={"percentile": p},
            ))
        
        return metrics
    
    def _get_field_value(self, entry: ParsedEntry, field: str) -> Any:
        """Get field value from a parsed entry."""
        if field == "level":
            return entry.level
        elif field == "source":
            return entry.source
        elif field == "message":
            return entry.message
        elif field in entry.metadata:
            return entry.metadata[field]
        return None
    
    def _get_time_bucket(self, timestamp: datetime, interval: str) -> str:
        """Get time bucket key for a timestamp."""
        if interval == "minute":
            return timestamp.strftime("%Y-%m-%d %H:%M")
        elif interval == "hour":
            return timestamp.strftime("%Y-%m-%d %H:00")
        elif interval == "day":
            return timestamp.strftime("%Y-%m-%d")
        return timestamp.isoformat()
    
    def _calculate_metric(
        self,
        entries: List[ParsedEntry],
        metric: AggregationType,
        value_field: Optional[str] = None,
    ) -> Any:
        """Calculate an aggregation metric."""
        if metric == AggregationType.COUNT:
            return len(entries)
        
        if value_field is None:
            return len(entries)
        
        values = []
        for entry in entries:
            value = self._get_field_value(entry, value_field)
            if value is not None and isinstance(value, (int, float)):
                values.append(float(value))
        
        if not values:
            return 0
        
        if metric == AggregationType.SUM:
            return sum(values)
        elif metric == AggregationType.AVG:
            return sum(values) / len(values)
        elif metric == AggregationType.MIN:
            return min(values)
        elif metric == AggregationType.MAX:
            return max(values)
        elif metric == AggregationType.COUNT:
            return len(values)
        
        return len(entries)
    
    def to_dataframe(self, result: AggregationResult) -> Any:
        """
        Convert aggregation result to pandas DataFrame.
        
        Args:
            result: AggregationResult to convert
            
        Returns:
            pandas DataFrame (if pandas available)
        """
        try:
            import pandas as pd
            data = []
            for group_name, metrics in result.groups.items():
                for metric in metrics:
                    row = {
                        "group": group_name,
                        "name": metric.name,
                        "value": metric.value,
                        "count": metric.count,
                    }
                    row.update(metric.group_by)
                    row.update(metric.metadata)
                    if metric.timestamp:
                        row["timestamp"] = metric.timestamp
                    data.append(row)
            return pd.DataFrame(data)
        except ImportError:
            raise ImportError("pandas is required for DataFrame conversion")
    
    def to_json(self, result: AggregationResult) -> str:
        """
        Convert aggregation result to JSON.
        
        Args:
            result: AggregationResult to convert
            
        Returns:
            JSON string
        """
        data = {
            "total_groups": result.total_groups,
            "aggregation_time": result.aggregation_time,
            "groups": {},
        }
        
        for group_name, metrics in result.groups.items():
            data["groups"][group_name] = [
                {
                    "name": m.name,
                    "value": m.value,
                    "count": m.count,
                    "timestamp": m.timestamp.isoformat() if m.timestamp else None,
                    "group_by": m.group_by,
                    "metadata": m.metadata,
                }
                for m in metrics
            ]
        
        return json.dumps(data, indent=2, default=str)
