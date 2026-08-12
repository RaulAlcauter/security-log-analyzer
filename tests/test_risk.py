import unittest


from src.risk import (
    calculate_alert_score,
    calculate_campaign_score,
    calculate_campaign_severity
)


class TestRisk(unittest.TestCase):

    def test_high_alert_score(self):
        alert = {
            "severity": "HIGH"
        }

        self.assertEqual(
            calculate_alert_score(alert),
            3
        )

    def test_campaign_score(self):
        campaign = {
            "related_alerts": [
                {"severity": "HIGH"},
                {"severity": "HIGH"}
            ]
        }

        self.assertEqual(
            calculate_campaign_score(campaign),
            6
        )

    def test_critical_campaign(self):
        self.assertEqual(
            calculate_campaign_severity(6),
            "CRITICAL"
        )

    def test_medium_campaign(self):
        self.assertEqual(
            calculate_campaign_severity(2),
            "MEDIUM"
        )


if __name__ == "__main__":
    unittest.main()