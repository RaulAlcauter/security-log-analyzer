from datetime import datetime

def parse_access_log(line):
    parts = line.strip().split()

    if len(parts) != 5:
        raise ValueError(f"Invalid access log entry: {line}")

    timestamp, source_ip, method, path, status = parts

    return {
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

if __name__ == "__main__":
    events = parse_access_log_file("logs/access.log")

    for event in events:
        print(event)