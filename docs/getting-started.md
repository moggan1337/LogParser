# Getting Started with LogParser

Welcome to LogParser! This guide will help you get up and running with the library.

## Installation

```bash
pip install logparser
```

## Your First Parse

```python
from logparser import LogParser, LogFormat

parser = LogParser(format=LogFormat.JSON)
entry = parser.parse_line('{"level": "INFO", "message": "Hello World"}')
print(entry.message)  # Hello World
```

## Next Steps

- Read the full [README.md](../README.md) for comprehensive documentation
- Check out [examples/basic_usage.py](../examples/basic_usage.py) for more examples
- Run [examples/sample_logs.py](../examples/sample_logs.py) to generate test data
