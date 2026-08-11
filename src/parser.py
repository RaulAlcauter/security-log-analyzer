from datetime import datetime

def parse_access_log(line):
    parts = line.strip().split()

    if len(parts) != 5:
        raise ValueError(f"Invalid access log entry: {line}")

    timestamp, source_ip, method, path, status = parts

    return {
        "type": "WEB",
        "timestamp": datetime.fromisoformat(timestamp),
        "source_ip": source_ip,
        "method": method,
        "path": path,
        "status": int(status)
    }

def parse_access_log_file(filename):
    events = []

    with open(filename, "r") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = parse_access_log(line)
                events.append(event)

            except ValueError as error:
                print(f"[WARNING] Line {line_number}: {error}")

    return events

def parse_auth_log(line):
    parts = line.strip().split()

    if len(parts) != 4:
        raise ValueError(f"Invalid auth log entry: {line}")

    timestamp, source_ip, event_type, username = parts

    if event_type not in {"LOGIN_SUCCESS", "LOGIN_FAILURE"}:
        raise ValueError(f"Unknown authentication event: {event_type}")

    return {
        "type": "AUTH",
        "timestamp": datetime.fromisoformat(timestamp),
        "source_ip": source_ip,
        "event": event_type,
        "username": username
    }

if __name__ == "__main__":
    with open("logs/auth.log", "r") as file:
        for line in file:
            event = parse_auth_log(line)
            print(event)