"""
Pattern Matching Module

Provides pattern matching and registry capabilities for
log analysis and extraction.
"""

from typing import Dict, List, Optional, Any, Callable, Pattern
from dataclasses import dataclass, field
from datetime import datetime
import re
import json


@dataclass
class Pattern:
    """Represents a log pattern."""
    name: str
    pattern: str
    description: str = ""
    fields: List[str] = field(default_factory=list)
    compiled: Optional[Pattern] = None  # Compiled regex
    enabled: bool = True
    
    def __post_init__(self):
        """Compile pattern after initialization."""
        if self.pattern and isinstance(self.pattern, str):
            self.compiled = re.compile(self.pattern)
    
    def match(self, text: str) -> Optional[re.Match]:
        """Match pattern against text."""
        if self.compiled:
            return self.compiled.match(text)
        return None
    
    def search(self, text: str) -> Optional[re.Match]:
        """Search pattern in text."""
        if self.compiled:
            return self.compiled.search(text)
        return None
    
    def findall(self, text: str) -> List[str]:
        """Find all matches in text."""
        if self.compiled:
            return self.compiled.findall(text)
        return []


@dataclass
class MatchResult:
    """Result of a pattern match."""
    pattern_name: str
    matched: bool
    groups: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    timestamp: Optional[datetime] = None


class PatternRegistry:
    """
    Registry for managing log patterns.
    
    Provides:
    - Pattern storage and retrieval
    - Pattern categorization
    - Pattern validation
    - Import/export patterns
    
    Example:
        >>> registry = PatternRegistry()
        >>> registry.add_pattern(
        ...     name="ip_address",
        ...     pattern=r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
        ...     description="IPv4 address"
        ... )
    """
    
    def __init__(self):
        """Initialize the pattern registry."""
        self._patterns: Dict[str, Pattern] = {}
        self._categories: Dict[str, List[str]] = {}  # category -> pattern names
    
    def add_pattern(
        self,
        name: str,
        pattern: str,
        description: str = "",
        fields: Optional[List[str]] = None,
        category: Optional[str] = None,
    ) -> Pattern:
        """
        Add a pattern to the registry.
        
        Args:
            name: Unique pattern name
            pattern: Regex pattern string
            description: Pattern description
            fields: List of field names for captured groups
            category: Optional category for organization
            
        Returns:
            Created Pattern object
        """
        if name in self._patterns:
            raise ValueError(f"Pattern '{name}' already exists")
        
        p = Pattern(
            name=name,
            pattern=pattern,
            description=description,
            fields=fields or [],
        )
        
        self._patterns[name] = p
        
        if category:
            if category not in self._categories:
                self._categories[category] = []
            self._categories[category].append(name)
        
        return p
    
    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern from the registry."""
        if name in self._patterns:
            del self._patterns[name]
            
            # Remove from categories
            for category in self._categories:
                if name in self._categories[category]:
                    self._categories[category].remove(name)
            
            return True
        return False
    
    def get_pattern(self, name: str) -> Optional[Pattern]:
        """Get a pattern by name."""
        return self._patterns.get(name)
    
    def get_patterns_by_category(self, category: str) -> List[Pattern]:
        """Get all patterns in a category."""
        names = self._categories.get(category, [])
        return [self._patterns[name] for name in names if name in self._patterns]
    
    def list_patterns(self, category: Optional[str] = None) -> List[Pattern]:
        """List all patterns, optionally filtered by category."""
        if category:
            return self.get_patterns_by_category(category)
        return list(self._patterns.values())
    
    def validate_pattern(self, pattern: str) -> bool:
        """Validate a pattern string."""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False
    
    def export_to_json(self) -> str:
        """Export patterns to JSON."""
        data = {
            "patterns": [
                {
                    "name": p.name,
                    "pattern": p.pattern,
                    "description": p.description,
                    "fields": p.fields,
                }
                for p in self._patterns.values()
            ],
            "categories": self._categories,
        }
        return json.dumps(data, indent=2)
    
    def import_from_json(self, json_str: str) -> int:
        """
        Import patterns from JSON.
        
        Returns:
            Number of patterns imported
        """
        data = json.loads(json_str)
        count = 0
        
        for p_data in data.get("patterns", []):
            try:
                self.add_pattern(
                    name=p_data["name"],
                    pattern=p_data["pattern"],
                    description=p_data.get("description", ""),
                    fields=p_data.get("fields", []),
                )
                count += 1
            except ValueError:
                pass  # Skip duplicates
        
        return count


class PatternMatcher:
    """
    Matcher for applying patterns to log data.
    
    Features:
    - Multiple pattern matching
    - Named group extraction
    - Pattern chaining
    - Match filtering
    
    Example:
        >>> matcher = PatternMatcher()
        >>> matcher.add_pattern("timestamp", r"\\d{4}-\\d{2}-\\d{2}")
        >>> result = matcher.match("2024-01-15 10:30:00 Error occurred")
    """
    
    def __init__(self, registry: Optional[PatternRegistry] = None):
        """
        Initialize the pattern matcher.
        
        Args:
            registry: Optional pattern registry to use
        """
        self.registry = registry or PatternRegistry()
        self._custom_patterns: List[Pattern] = []
        self._match_filters: List[Callable[[MatchResult], bool]] = []
    
    def add_pattern(
        self,
        name: str,
        pattern: str,
        description: str = "",
        fields: Optional[List[str]] = None,
    ) -> None:
        """
        Add a pattern for matching.
        
        Args:
            name: Pattern name
            pattern: Regex pattern string
            description: Pattern description
            fields: Field names for captured groups
        """
        p = Pattern(
            name=name,
            pattern=pattern,
            description=description,
            fields=fields or [],
        )
        self._custom_patterns.append(p)
    
    def remove_pattern(self, name: str) -> bool:
        """Remove a custom pattern."""
        for i, p in enumerate(self._custom_patterns):
            if p.name == name:
                self._custom_patterns.pop(i)
                return True
        return False
    
    def add_filter(self, filter_func: Callable[[MatchResult], bool]) -> None:
        """Add a filter function for match results."""
        self._match_filters.append(filter_func)
    
    def match(self, text: str, pattern_name: Optional[str] = None) -> Optional[MatchResult]:
        """
        Match text against patterns.
        
        Args:
            text: Text to match
            pattern_name: Optional specific pattern name (first match wins)
            
        Returns:
            MatchResult if a pattern matches, None otherwise
        """
        patterns = [self.registry.get_pattern(pattern_name)] if pattern_name else None
        
        if patterns is None:
            patterns = self._custom_patterns + list(self.registry._patterns.values())
        
        for pattern in patterns:
            if not pattern or not pattern.enabled:
                continue
            
            match = pattern.match(text)
            if match:
                result = MatchResult(
                    pattern_name=pattern.name,
                    matched=True,
                    groups=self._extract_groups(match, pattern.fields),
                    text=text,
                )
                
                # Apply filters
                if all(f(result) for f in self._match_filters):
                    return result
        
        return None
    
    def match_all(self, text: str) -> List[MatchResult]:
        """
        Match text against all patterns.
        
        Args:
            text: Text to match
            
        Returns:
            List of all matching results
        """
        results = []
        all_patterns = self._custom_patterns + list(self.registry._patterns.values())
        
        for pattern in all_patterns:
            if not pattern.enabled:
                continue
            
            match = pattern.match(text)
            if match:
                result = MatchResult(
                    pattern_name=pattern.name,
                    matched=True,
                    groups=self._extract_groups(match, pattern.fields),
                    text=text,
                )
                
                if all(f(result) for f in self._match_filters):
                    results.append(result)
        
        return results
    
    def search(self, text: str, pattern_name: Optional[str] = None) -> Optional[MatchResult]:
        """
        Search for pattern in text (not anchored).
        
        Args:
            text: Text to search
            pattern_name: Optional specific pattern name
            
        Returns:
            MatchResult if pattern found, None otherwise
        """
        patterns = [self.registry.get_pattern(pattern_name)] if pattern_name else None
        
        if patterns is None:
            patterns = self._custom_patterns + list(self.registry._patterns.values())
        
        for pattern in patterns:
            if not pattern.enabled:
                continue
            
            match = pattern.search(text)
            if match:
                result = MatchResult(
                    pattern_name=pattern.name,
                    matched=True,
                    groups=self._extract_groups(match, pattern.fields),
                    text=text,
                )
                
                if all(f(result) for f in self._match_filters):
                    return result
        
        return None
    
    def extract(self, text: str, pattern_name: str) -> List[Dict[str, str]]:
        """
        Extract all matches from text.
        
        Args:
            text: Text to extract from
            pattern_name: Pattern name to use
            
        Returns:
            List of extracted group dictionaries
        """
        pattern = self.registry.get_pattern(pattern_name) or self._find_custom_pattern(pattern_name)
        
        if not pattern or not pattern.compiled:
            return []
        
        matches = []
        for match in pattern.compiled.finditer(text):
            matches.append(self._extract_groups(match, pattern.fields))
        
        return matches
    
    def _find_custom_pattern(self, name: str) -> Optional[Pattern]:
        """Find a custom pattern by name."""
        for p in self._custom_patterns:
            if p.name == name:
                return p
        return None
    
    def _extract_groups(self, match: re.Match, fields: List[str]) -> Dict[str, str]:
        """Extract named groups from a match."""
        groups = match.groupdict()
        
        # Map to field names if provided
        if fields and len(fields) == len(match.groups()):
            return dict(zip(fields, match.groups()))
        
        return groups


# Pre-defined common patterns
COMMON_PATTERNS = {
    "timestamp_iso": {
        "pattern": r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        "description": "ISO 8601 timestamp",
        "fields": ["timestamp"],
    },
    "timestamp_common": {
        "pattern": r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
        "description": "Common log timestamp",
        "fields": ["timestamp"],
    },
    "ip_address": {
        "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "description": "IPv4 address",
        "fields": ["ip"],
    },
    "ipv6_address": {
        "pattern": r"[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]*",
        "description": "IPv6 address",
        "fields": ["ip"],
    },
    "email": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "description": "Email address",
        "fields": ["email"],
    },
    "url": {
        "pattern": r"https?://[^\s<>\"]+",
        "description": "URL",
        "fields": ["url"],
    },
    "uuid": {
        "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "description": "UUID",
        "fields": ["uuid"],
    },
    "http_status": {
        "pattern": r"\b[1-5]\d{2}\b",
        "description": "HTTP status code",
        "fields": ["status"],
    },
    "error_level": {
        "pattern": r"\b(ERROR|WARN(?:ING)?|INFO|DEBUG|CRITICAL|FATAL)\b",
        "description": "Log level",
        "fields": ["level"],
    },
    "http_method": {
        "pattern": r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b",
        "description": "HTTP method",
        "fields": ["method"],
    },
    "file_path": {
        "pattern": r"(?:/[\w.-]+)+/?",
        "description": "Unix file path",
        "fields": ["path"],
    },
    "windows_path": {
        "pattern": r"[A-Za-z]:\\[\w.\\]+",
        "description": "Windows file path",
        "fields": ["path"],
    },
    "port_number": {
        "pattern": r":\d{2,5}\b",
        "description": "Port number",
        "fields": ["port"],
    },
    "request_id": {
        "pattern": r"\brequest[_-]?id[:\s]+([a-f0-9-]+)",
        "description": "Request ID",
        "fields": ["request_id"],
    },
    "user_id": {
        "pattern": r"\b(?:user[_-]?id|uid)[:\s=]+(\d+|\w+)",
        "description": "User ID",
        "fields": ["user_id"],
    },
}


def create_common_patterns(registry: PatternRegistry) -> None:
    """Add common patterns to a registry."""
    for name, info in COMMON_PATTERNS.items():
        registry.add_pattern(
            name=name,
            pattern=info["pattern"],
            description=info["description"],
            fields=info["fields"],
            category="common",
        )
