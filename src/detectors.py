from collections import defaultdict
from datetime import timedelta

def detect_brute_force(events, threshold=10, window_seconds=60):
    failures_by_ip = defaultdict(list)

    for event in events:
        if event["event_type"] == "LOGIN_FAILURE":
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
                    "failed_attempts": len(failures_in_window),
                    "window_seconds": window_seconds
                })
                break

    return alerts