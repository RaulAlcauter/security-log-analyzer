from datetime import timedelta
from risk import calculate_campaign_score, calculate_campaign_severity

def correlate_alerts(alerts, window_seconds=300):
    alerts_by_ip = {}

    for alert in alerts:
        source_ip = alert["source_ip"]

        if source_ip not in alerts_by_ip:
            alerts_by_ip[source_ip] = []

        alerts_by_ip[source_ip].append(alert)

    correlated_alerts = []

    for source_ip, ip_alerts in alerts_by_ip.items():
        ip_alerts.sort(key=lambda alert: alert["timestamp"])

        for i in range(len(ip_alerts)):
            window_start = ip_alerts[i]["timestamp"]
            window_end = window_start + timedelta(seconds=window_seconds)

            alerts_in_window = [
                alert
                for alert in ip_alerts[i:]
                if alert["timestamp"] <= window_end
            ]

            alert_types = {
                alert["type"]
                for alert in alerts_in_window
            }

            if len(alert_types) >= 2:
                first_seen = alerts_in_window[0]["timestamp"]
                last_seen = alerts_in_window[-1]["timestamp"]
                campaign = {
                    "type": "ATTACK_CAMPAIGN",
                    "severity": "CRITICAL",
                    "source_ip": source_ip,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "duration_seconds": (
                        last_seen - first_seen
                    ).total_seconds(),
                    "related_alerts": alerts_in_window
                }

                campaign_score = calculate_campaign_score(campaign)
                campaign["risk_score"] = campaign_score
                campaign["severity"] = calculate_campaign_severity(campaign_score)

                correlated_alerts.append(campaign)
                
                break

    return correlated_alerts