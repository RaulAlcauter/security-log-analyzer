from detectors import detect_brute_force
from parser import parse_auth_log


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


if __name__ == "__main__":
    events = load_auth_events("logs/auth.log")

    alerts = detect_brute_force(events)

    for alert in alerts:
        print(alert)