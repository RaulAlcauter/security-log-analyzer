import json

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

        if alert["type"] == "ATTACK_CAMPAIGN":
            print(f"First seen: {alert['first_seen']}")
            print(f"Last seen : {alert['last_seen']}")
            print(f"Duration  : {alert['duration_seconds']} seconds")
            print(f"Risk score: {alert['risk_score']}")
            
            print("Related alerts:")

            for related_alert in alert["related_alerts"]:
                print(f"  [{related_alert['severity']}] {related_alert['type']}")

                if "path" in related_alert:
                    print(f"    Endpoint: {related_alert['path']}")

                if "pattern" in related_alert:
                    print(f"    Pattern : {related_alert['pattern']}")

            print("-" * 60)
            continue

        if "path" in alert:
            print(f"Endpoint  : {alert['path']}")

        if "failed_attempts" in alert:
            print(f"Attempts  : {alert['failed_attempts']}")
            print(f"Window    : {alert['window_seconds']} seconds")

        if "pattern" in alert:
            print(f"Pattern   : {alert['pattern']}")

        if "related_alerts" in alert:
            print("Related alerts:")
            for related_alert in alert["related_alerts"]:
                print(f"  - {related_alert}")

        print("-" * 60)

    print(f"\nTotal alerts: {len(alerts)}")

def print_alerts_json(alerts):
    print(json.dumps(alerts, indent=4, default=str))