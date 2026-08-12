def print_alerts(alerts):
    print("=" * 60)
    print("SECURITY LOG ANALYZER")
    print("=" * 60)

    if not alerts:
        print("\nNo security alerts detected.")
        return

    print(f"\nALERTS FOUND: {len(alerts)}\n")

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['type']}")
        print(f"Source IP : {alert['source_ip']}")

        if "path" in alert:
            print(f"Endpoint  : {alert['path']}")

        if "failed_attempts" in alert:
            print(f"Attempts  : {alert['failed_attempts']}")
            print(f"Window    : {alert['window_seconds']} seconds")

        if "pattern" in alert:
            print(f"Pattern   : {alert['pattern']}")

        print("-" * 60)

    print(f"\nTotal alerts: {len(alerts)}")