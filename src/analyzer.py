from detectors import run_all_detectors
from parser import parse_access_log, parse_auth_log
from reporter import print_alerts, print_alerts_json
from config import load_config
import argparse
from correlator import correlate_alerts

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze security logs and detect suspicious activity."
    )

    parser.add_argument(
        "--access-log",
        default="logs/access.log",
        help="Path to the web access log."
    )

    parser.add_argument(
        "--auth-log",
        default="logs/auth.log",
        help="Path to the authentication log."
    )

    parser.add_argument(
        "--config",
        default="config/rules.json",
        help="Path to the detection rules configuration."
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format."
    )

    return parser.parse_args()

def load_auth_events(filename):
    events = []

    with open(filename, "r") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = parse_auth_log(line)
                events.append(event)

            except ValueError as error:
                print(f"[WARNING] Auth log line {line_number}: {error}")

    return events

def load_access_events(filename):
    events = []

    with open(filename, "r") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = parse_access_log(line)
                events.append(event)

            except ValueError as error:
                print(f"[WARNING] Access log line {line_number}: {error}")

    return events

if __name__ == "__main__":
    args = parse_arguments()

    config = load_config(args.config)

    access_events = load_access_events(args.access_log)
    auth_events = load_auth_events(args.auth_log)

    access_alerts = run_all_detectors(access_events, config)
    auth_alerts = run_all_detectors(auth_events, config)

    alerts = access_alerts + auth_alerts

    correlation_alerts = correlate_alerts(alerts)

    alerts.extend(correlation_alerts)

    if args.format == "json":
        print_alerts_json(alerts)
    else:
        print_alerts(alerts)