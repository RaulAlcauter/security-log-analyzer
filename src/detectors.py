from collections import defaultdict
from datetime import timedelta
import re 
from urllib.parse import unquote

def normalize_url(value, max_decodes=3):
    current = value

    for _ in range(max_decodes):
        decoded = unquote(current)

        if decoded == current:
            break

        current = decoded

    return current

def detect_brute_force(events, threshold=10, window_seconds=60):
    failures_by_ip = defaultdict(list)

    for event in events:
        if event["type"] == "AUTH" and event["event"] == "LOGIN_FAILURE":
            failures_by_ip[event["source_ip"]].append(event)

    alerts = []

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])

        for i in range(len(failures)):
            window_start = failures[i]["timestamp"]
            window_end = window_start + timedelta(seconds=window_seconds)

            failures_in_window = [
                event
                for event in failures[i:]
                if event["timestamp"] <= window_end
            ]

            if len(failures_in_window) >= threshold:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "source_ip": source_ip,
                    "timestamp": failures[i]["timestamp"],
                    "failed_attempts": len(failures_in_window),
                    "window_seconds": window_seconds
                })
                break

    return alerts

def detect_sql_injection(events):
    sql_patterns = [
        r"\bunion\s+select\b",
        r"\bor\s+\d+\s*=\s*\d+\b",
        r"\band\s+\d+\s*=\s*\d+\b",
        r"'\s*or\s*'",
        r"--",
        r"/\*.*\*/",
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\("
    ]

    return detect_web_patterns(
        events,
        sql_patterns,
        "SQL_INJECTION"
    )

def detect_xss(events):
    xss_patterns = [
        r"<\s*script\b",
        r"javascript\s*:",
        r"<\s*iframe\b",
        r"<\s*object\b",
        r"\bonerror\s*=",
        r"\bonload\s*="
    ]

    return detect_web_patterns(
        events,
        xss_patterns,
        "XSS"
    )

def detect_path_traversal(events):
    traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"windows/system32"
    ]

    return detect_web_patterns(
        events,
        traversal_patterns,
        "PATH_TRAVERSAL"
    )

def detect_web_patterns(events, patterns, alert_type, severity="HIGH"):
    alerts = []

    for event in events:
        if event["type"] != "WEB":
            continue

        decoded_path = normalize_url(event["path"])

        for pattern in patterns:
            if re.search(pattern, decoded_path, re.IGNORECASE):
                alerts.append({
                    "type": alert_type,
                    "severity": severity,
                    "source_ip": event["source_ip"],
                    "path": event["path"],
                    "pattern": pattern,
                    "timestamp": event["timestamp"]
                })
                break

    return alerts

def run_all_detectors(events, config):
    alerts = []

    brute_force_config = config["brute_force"]

    alerts.extend(
        detect_brute_force(
            events,
            threshold=brute_force_config["threshold"],
            window_seconds=brute_force_config["window_seconds"]
        )
    )
    alerts.extend(detect_sql_injection(events))
    alerts.extend(detect_xss(events))
    alerts.extend(detect_path_traversal(events))

    return alerts