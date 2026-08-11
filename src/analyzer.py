from detectors import detect_brute_force, detect_sql_injection
from parser import parse_auth_log, parse_access_log


def load_auth_events(filename):
    events = []

    with open(filename, "r") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = parse_auth_log(line)
                events.append(event)

            except ValueError as error:
                print(f"[WARNING] Line {line_number}: {error}")

    return events

def load_access_events(filename):
    events = []

    with open(filename, "r") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = parse_access_log(line)
                events.append(event)

            except ValueError as error:
                print(f"[WARNING] Line {line_number}: {error}")

    return events

if __name__ == "__main__":
    events = load_access_events("logs/access.log")

    alerts = detect_sql_injection(events)

    for alert in alerts:
        print(alert)