from detectors import run_all_detectors
from parser import parse_access_log, parse_auth_log
from reporter import print_alerts

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
    access_events = load_access_events("logs/access.log")
    auth_events = load_auth_events("logs/auth.log")

    access_alerts = run_all_detectors(access_events)
    auth_alerts = run_all_detectors(auth_events)

    alerts = access_alerts + auth_alerts

    print_alerts(alerts)