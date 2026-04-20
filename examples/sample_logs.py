#!/usr/bin/env python3
"""
Sample Log Generator

Generate sample log files for testing and demonstration.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_json_logs(filename: str, count: int = 1000):
    """Generate JSON-formatted log file."""
    levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    services = ["api-gateway", "auth-service", "user-service", "payment-service"]
    messages = [
        "Request processed successfully",
        "User authentication completed",
        "Database query executed",
        "Cache hit for key: {}",
        "Connection established",
        "Timeout waiting for response",
        "Invalid input received",
        "Rate limit exceeded",
        "Session expired",
        "Configuration loaded",
    ]
    
    start_time = datetime(2024, 1, 15, 10, 0, 0)
    
    with open(filename, "w") as f:
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i)
            level = random.choice(levels)
            
            # Higher probability of INFO
            if random.random() < 0.6:
                level = "INFO"
            
            msg_template = random.choice(messages)
            message = msg_template.format(random.randint(1000, 9999))
            
            log_entry = {
                "timestamp": timestamp.isoformat() + "Z",
                "level": level,
                "message": message,
                "service": random.choice(services),
                "request_id": f"req-{i:08d}",
                "duration_ms": random.randint(5, 500),
            }
            
            if level in ("ERROR", "CRITICAL"):
                log_entry["error_code"] = random.randint(1000, 5999)
                log_entry["stack_trace"] = f"Error at line {random.randint(1, 100)}"
            
            f.write(json.dumps(log_entry) + "\n")
    
    print(f"Generated {count} JSON log entries in {filename}")


def generate_apache_logs(filename: str, count: int = 1000):
    """Generate Apache Combined log format."""
    ips = ["192.168.1." + str(i) for i in range(1, 50)]
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    paths = ["/", "/api/users", "/api/products", "/api/orders", "/login", "/static/css/main.css", "/static/js/app.js"]
    status_codes = [200, 200, 200, 200, 201, 204, 301, 400, 401, 403, 404, 500, 502, 503]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.68.0",
        "Python-requests/2.28.0",
    ]
    referrers = ["-", "https://example.com", "https://google.com", "https://github.com"]
    
    start_time = datetime(2024, 1, 15, 10, 0, 0)
    
    with open(filename, "w") as f:
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 3)
            
            # Format: 15/Jan/2024:10:30:00 +0000
            ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
            
            ip = random.choice(ips)
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choice(status_codes)
            bytes_sent = random.randint(200, 50000)
            referrer = random.choice(referrers)
            user_agent = random.choice(user_agents)
            
            log_line = f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "{referrer}" "{user_agent}"'
            f.write(log_line + "\n")
    
    print(f"Generated {count} Apache log entries in {filename}")


def generate_nginx_logs(filename: str, count: int = 1000):
    """Generate nginx access log format."""
    ips = ["10.0.0." + str(i) for i in range(1, 100)]
    methods = ["GET", "POST"]
    paths = ["/", "/api/", "/api/v1/users", "/api/v1/health", "/static/"]
    status_codes = [200, 200, 200, 304, 400, 401, 404, 500]
    
    start_time = datetime(2024, 1, 15, 10, 0, 0)
    
    with open(filename, "w") as f:
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 2)
            ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
            
            ip = random.choice(ips)
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choice(status_codes)
            bytes_sent = random.randint(100, 10000)
            
            log_line = f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "-"'
            f.write(log_line + "\n")
    
    print(f"Generated {count} nginx log entries in {filename}")


def generate_syslog_logs(filename: str, count: int = 1000):
    """Generate syslog format."""
    programs = ["sshd", "systemd", "NetworkManager", "docker", "nginx", "cron", "kernel"]
    messages = [
        "Started user service",
        "Connection established from {}",
        "Failed to connect to server",
        "Configuration reloaded",
        "Process exited with code {}",
        "Memory limit reached",
        "Disk space warning",
        "Service started",
    ]
    
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    
    start_time = datetime(2024, 1, 15, 10, 0, 0)
    
    with open(filename, "w") as f:
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 5)
            
            month = months[timestamp.month - 1]
            day = timestamp.day
            time_str = timestamp.strftime("%H:%M:%S")
            
            program = random.choice(programs)
            pid = random.randint(1000, 65000)
            msg_template = random.choice(messages)
            
            if "{}" in msg_template:
                if "IP" in msg_template:
                    message = msg_template.format(f"192.168.1.{random.randint(1, 255)}")
                else:
                    message = msg_template.format(random.randint(0, 255))
            else:
                message = msg_template
            
            log_line = f'{month} {day:2d} {time_str} server {program}[{pid}]: {message}'
            f.write(log_line + "\n")
    
    print(f"Generated {count} syslog entries in {filename}")


def generate_mixed_logs(filename: str, count: int = 1000):
    """Generate mixed format log file (useful for testing auto-detection)."""
    
    with open(filename, "w") as f:
        for i in range(count):
            format_type = i % 4
            
            if format_type == 0:
                # JSON
                entry = {
                    "ts": datetime.now().isoformat(),
                    "lvl": random.choice(["INFO", "DEBUG"]),
                    "msg": f"Sample message {i}",
                }
                f.write(json.dumps(entry) + "\n")
            
            elif format_type == 1:
                # Apache
                f.write(f'192.168.1.{i%255} - - [15/Jan/2024:10:30:00 +0000] "GET /path HTTP/1.1" 200 1234\n')
            
            elif format_type == 2:
                # nginx
                f.write(f'10.0.0.{i%255} - - [15/Jan/2024:10:30:00 +0000] "POST /api HTTP/1.1" 201 256\n')
            
            else:
                # Syslog
                f.write(f'Jan 15 10:30:00 server app[{i}]: Message {i}\n')
    
    print(f"Generated {count} mixed-format log entries in {filename}")


def main():
    """Generate all sample log files."""
    output_dir = Path(__file__).parent / "sample_logs"
    output_dir.mkdir(exist_ok=True)
    
    generate_json_logs(output_dir / "sample.json.log", count=1000)
    generate_apache_logs(output_dir / "sample.apache.log", count=1000)
    generate_nginx_logs(output_dir / "sample.nginx.log", count=1000)
    generate_syslog_logs(output_dir / "sample.syslog", count=1000)
    generate_mixed_logs(output_dir / "sample.mixed.log", count=500)
    
    print(f"\nAll sample logs generated in: {output_dir}")


if __name__ == "__main__":
    main()
