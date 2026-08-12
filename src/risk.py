SEVERITY_SCORES = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def calculate_alert_score(alert):
    return SEVERITY_SCORES.get(alert["severity"], 0)


def calculate_campaign_score(campaign):
    related_alerts = campaign["related_alerts"]

    score = sum(
        calculate_alert_score(alert)
        for alert in related_alerts
    )

    return score


def calculate_campaign_severity(score):
    if score >= 6:
        return "CRITICAL"
    elif score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"