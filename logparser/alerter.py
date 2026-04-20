"""
Log Alerter Module

Provides alerting capabilities for log monitoring with
configurable rules and notification channels.
"""

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import re

from .parser import ParsedEntry, ParseResult
from .analyzer import LogAnalyzer, Anomaly, AnomalyType


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status values."""
    ACTIVE = "active"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"


@dataclass
class AlertRule:
    """Defines an alerting rule."""
    name: str
    condition: str  # e.g., "level == 'ERROR'"
    severity: AlertSeverity = AlertSeverity.WARNING
    message_template: str = "Alert: {condition}"
    enabled: bool = True
    cooldown_seconds: int = 300  # Prevent alert flooding
    match_count: int = 1  # Number of matches to trigger


@dataclass
class Alert:
    """Represents a triggered alert."""
    id: str
    rule: AlertRule
    severity: AlertSeverity
    message: str
    timestamp: datetime
    triggered_at: datetime = field(default_factory=datetime.now)
    count: int = 1
    status: AlertStatus = AlertStatus.ACTIVE
    entries: List[ParsedEntry] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "rule_name": self.rule.name,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "triggered_at": self.triggered_at.isoformat(),
            "count": self.count,
            "status": self.status.value,
            "entry_count": len(self.entries),
            "metadata": self.metadata,
        }


@dataclass
class AlertEvent:
    """Container for alert events."""
    alerts: List[Alert] = field(default_factory=list)
    total_triggered: int = 0
    total_resolved: int = 0
    processing_time: float = 0.0


class NotificationChannel(ABC):
    """Abstract base class for notification channels."""
    
    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send notification for an alert."""
        pass


class LogAlerter:
    """
    Alerting system for log monitoring.
    
    Features:
    - Configurable alert rules with conditions
    - Multiple notification channels (webhook, email, Slack, etc.)
    - Alert deduplication and cooldown
    - Severity-based filtering
    - Alert history and tracking
    
    Example:
        >>> alerter = LogAlerter()
        >>> alerter.add_rule(
        ...     name="High Error Rate",
        ...     condition="level == 'ERROR'",
        ...     severity=AlertSeverity.ERROR
        ... )
        >>> events = alerter.process_entries(entries)
    """
    
    def __init__(self):
        """Initialize the alerter."""
        self.rules: List[AlertRule] = []
        self.channels: List[NotificationChannel] = []
        self.alert_history: List[Alert] = []
        self.active_alerts: Dict[str, Alert] = {}
        self._last_triggered: Dict[str, datetime] = {}
        self._analyzer = LogAnalyzer()
    
    def add_rule(
        self,
        name: str,
        condition: str,
        severity: AlertSeverity = AlertSeverity.WARNING,
        message_template: Optional[str] = None,
        cooldown_seconds: int = 300,
        match_count: int = 1,
    ) -> None:
        """
        Add an alert rule.
        
        Args:
            name: Unique rule name
            condition: Condition expression (e.g., "level == 'ERROR'")
            severity: Alert severity level
            message_template: Custom message template
            cooldown_seconds: Cooldown period to prevent flooding
            match_count: Number of matches to trigger alert
        """
        rule = AlertRule(
            name=name,
            condition=condition,
            severity=severity,
            message_template=message_template or f"Alert: {condition}",
            cooldown_seconds=cooldown_seconds,
            match_count=match_count,
        )
        self.rules.append(rule)
    
    def remove_rule(self, name: str) -> bool:
        """Remove an alert rule by name."""
        for i, rule in enumerate(self.rules):
            if rule.name == name:
                self.rules.pop(i)
                return True
        return False
    
    def add_channel(self, channel: NotificationChannel) -> None:
        """Add a notification channel."""
        self.channels.append(channel)
    
    def process_entries(
        self,
        entries: List[ParsedEntry],
        auto_anomaly_detection: bool = True,
    ) -> AlertEvent:
        """
        Process entries and trigger alerts.
        
        Args:
            entries: List of parsed log entries
            auto_anomaly_detection: Enable automatic anomaly-based alerts
            
        Returns:
            AlertEvent with triggered alerts
        """
        import time
        start_time = time.time()
        
        event = AlertEvent()
        triggered_rules: Dict[str, List[ParsedEntry]] = {
            rule.name: [] for rule in self.rules if rule.enabled
        }
        
        # Check each entry against rules
        for entry in entries:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                if self._evaluate_condition(entry, rule.condition):
                    triggered_rules[rule.name].append(entry)
        
        # Process triggered rules
        for rule_name, matched_entries in triggered_rules.items():
            if len(matched_entries) >= rule.match_count:
                alert = self._create_alert(
                    rule=self._get_rule(rule_name),
                    entries=matched_entries,
                )
                
                if alert:
                    event.alerts.append(alert)
                    event.total_triggered += 1
                    self.active_alerts[alert.id] = alert
                    self.alert_history.append(alert)
        
        # Auto anomaly detection
        if auto_anomaly_detection:
            anomalies = self._analyzer.detect_anomalies(entries)
            anomaly_alerts = self._create_anomaly_alerts(anomalies)
            event.alerts.extend(anomaly_alerts)
            event.total_triggered += len(anomaly_alerts)
        
        # Send notifications
        for alert in event.alerts:
            self._send_notifications(alert)
        
        # Check for resolved alerts
        event.total_resolved = self._resolve_stale_alerts(entries)
        
        event.processing_time = time.time() - start_time
        return event
    
    def process_result(
        self,
        result: ParseResult,
        auto_anomaly_detection: bool = True,
    ) -> AlertEvent:
        """
        Process a ParseResult and trigger alerts.
        
        Args:
            result: ParseResult from LogParser
            auto_anomaly_detection: Enable automatic anomaly-based alerts
            
        Returns:
            AlertEvent with triggered alerts
        """
        return self.process_entries(result.entries, auto_anomaly_detection)
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an active alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].status = AlertStatus.ACKNOWLEDGED
            return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Manually resolve an alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            del self.active_alerts[alert_id]
            return True
        return False
    
    def get_active_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
    ) -> List[Alert]:
        """Get all active alerts, optionally filtered by severity."""
        alerts = list(self.active_alerts.values())
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return sorted(alerts, key=lambda x: x.triggered_at, reverse=True)
    
    def get_alert_history(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> List[Alert]:
        """Get alert history."""
        history = self.alert_history
        
        if since:
            history = [a for a in history if a.triggered_at >= since]
        
        return sorted(history, key=lambda x: x.triggered_at, reverse=True)[:limit]
    
    def _get_rule(self, name: str) -> AlertRule:
        """Get rule by name."""
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise ValueError(f"Rule not found: {name}")
    
    def _evaluate_condition(self, entry: ParsedEntry, condition: str) -> bool:
        """Evaluate a condition against an entry."""
        # Simple condition evaluation
        # Supports: level == 'ERROR', source == 'nginx', message contains 'failed'
        
        condition = condition.strip()
        
        # Handle '==' comparisons
        if "==" in condition:
            field, value = condition.split("==")
            field = field.strip()
            value = value.strip().strip("'\"")
            
            entry_value = self._get_entry_value(entry, field)
            return str(entry_value) == value
        
        # Handle '!=' comparisons
        if "!=" in condition:
            field, value = condition.split("!=")
            field = field.strip()
            value = value.strip().strip("'\"")
            
            entry_value = self._get_entry_value(entry, field)
            return str(entry_value) != value
        
        # Handle 'contains'
        if "contains" in condition:
            match = re.match(r"(\w+)\s+contains\s+'([^']+)'", condition)
            if match:
                field, value = match.groups()
                entry_value = self._get_entry_value(entry, field)
                return value in str(entry_value)
        
        # Handle 'matches' (regex)
        if "matches" in condition:
            match = re.match(r"(\w+)\s+matches\s+'([^']+)'", condition)
            if match:
                field, pattern = match.groups()
                entry_value = self._get_entry_value(entry, field)
                return bool(re.search(pattern, str(entry_value)))
        
        return False
    
    def _get_entry_value(self, entry: ParsedEntry, field: str) -> Any:
        """Get value from entry for field name."""
        if field == "level":
            return entry.level
        elif field == "source":
            return entry.source
        elif field == "message":
            return entry.message
        elif field in entry.metadata:
            return entry.metadata[field]
        return None
    
    def _create_alert(
        self,
        rule: AlertRule,
        entries: List[ParsedEntry],
    ) -> Optional[Alert]:
        """Create an alert from triggered rule."""
        # Check cooldown
        if rule.name in self._last_triggered:
            last = self._last_triggered[rule.name]
            if (datetime.now() - last).total_seconds() < rule.cooldown_seconds:
                return None
        
        alert_id = f"{rule.name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        message = rule.message_template.format(
            rule=rule.name,
            condition=rule.condition,
            count=len(entries),
            entries=entries[:3],  # Include first 3 entries
        )
        
        alert = Alert(
            id=alert_id,
            rule=rule,
            severity=rule.severity,
            message=message,
            timestamp=datetime.now(),
            count=len(entries),
            entries=entries[:10],  # Store first 10 entries
            metadata={"first_entry": entries[0].raw if entries else ""},
        )
        
        self._last_triggered[rule.name] = datetime.now()
        return alert
    
    def _create_anomaly_alerts(
        self,
        anomalies: List[Anomaly],
    ) -> List[Alert]:
        """Create alerts from detected anomalies."""
        alerts = []
        
        severity_map = {
            AnomalyType.VOLUME_SPIKE: AlertSeverity.WARNING,
            AnomalyType.ERROR_RATE: AlertSeverity.ERROR,
            AnomalyType.LATENCY_INCREASE: AlertSeverity.WARNING,
            AnomalyType.PATTERN_BREAK: AlertSeverity.INFO,
            AnomalyType.UNUSUAL_SOURCE: AlertSeverity.INFO,
        }
        
        for anomaly in anomalies:
            rule = AlertRule(
                name=f"anomaly_{anomaly.type.value}",
                condition=f"anomaly == '{anomaly.type.value}'",
                severity=severity_map.get(anomaly.type, AlertSeverity.INFO),
                message_template=anomaly.description,
            )
            
            alert_id = f"anomaly_{anomaly.type.value}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            alert = Alert(
                id=alert_id,
                rule=rule,
                severity=severity_map.get(anomaly.type, AlertSeverity.INFO),
                message=anomaly.description,
                timestamp=anomaly.timestamp,
                count=anomaly.affected_count,
                metadata=anomaly.details,
            )
            
            alerts.append(alert)
        
        return alerts
    
    def _send_notifications(self, alert: Alert) -> None:
        """Send alert to all configured channels."""
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as e:
                # Log but don't fail on notification errors
                import logging
                logging.error(f"Failed to send alert via {channel}: {e}")
    
    def _resolve_stale_alerts(self, entries: List[ParsedEntry]) -> int:
        """Check and resolve alerts that are no longer occurring."""
        resolved_count = 0
        
        for alert_id, alert in list(self.active_alerts.items()):
            if alert.status == AlertStatus.RESOLVED:
                continue
            
            # Check if new entries match the alert condition
            still_matching = sum(
                1 for e in entries
                if self._evaluate_condition(e, alert.rule.condition)
            )
            
            if still_matching == 0:
                alert.status = AlertStatus.RESOLVED
                del self.active_alerts[alert_id]
                resolved_count += 1
        
        return resolved_count
    
    def to_json(self) -> str:
        """Export alerter configuration and state to JSON."""
        data = {
            "rules": [
                {
                    "name": r.name,
                    "condition": r.condition,
                    "severity": r.severity.value,
                    "message_template": r.message_template,
                    "enabled": r.enabled,
                    "cooldown_seconds": r.cooldown_seconds,
                    "match_count": r.match_count,
                }
                for r in self.rules
            ],
            "active_alerts": [a.to_dict() for a in self.active_alerts.values()],
            "total_history": len(self.alert_history),
        }
        return json.dumps(data, indent=2, default=str)


from abc import ABC, abstractmethod
