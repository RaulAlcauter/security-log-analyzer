import unittest

from datetime import datetime, timedelta

from src.correlator import correlate_alerts


class TestCorrelator(unittest.TestCase):

    def test_correlates_different_alert_types_from_same_ip(self):
        timestamp = datetime(2026, 8, 10, 10, 0, 0)

        alerts = [
            {
                "type": "SQL_INJECTION",
                "severity": "HIGH",
                "source_ip": "10.10.10.60",
                "timestamp": timestamp
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "source_ip": "10.10.10.60",
                "timestamp": timestamp + timedelta(seconds=10)
            }
        ]

        correlated = correlate_alerts(alerts)

        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["type"], "ATTACK_CAMPAIGN")
        self.assertEqual(correlated[0]["source_ip"], "10.10.10.60")
        self.assertEqual(
            correlated[0]["first_seen"],
            timestamp
        )

        self.assertEqual(
            correlated[0]["last_seen"],
            timestamp + timedelta(seconds=10)
        )

        self.assertEqual(
            correlated[0]["duration_seconds"],
            10
        )

        self.assertEqual(
            len(correlated[0]["related_alerts"]),
            2
        )

    def test_does_not_correlate_different_ips(self):
        timestamp = datetime(2026, 8, 10, 10, 0, 0)

        alerts = [
            {
                "type": "SQL_INJECTION",
                "severity": "HIGH",
                "source_ip": "10.10.10.60",
                "timestamp": timestamp
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "source_ip": "10.10.10.61",
                "timestamp": timestamp + timedelta(seconds=10)
            }
        ]

        correlated = correlate_alerts(alerts)

        self.assertEqual(len(correlated), 0)

    def test_does_not_correlate_alerts_outside_time_window(self):
        timestamp = datetime(2026, 8, 10, 10, 0, 0)

        alerts = [
            {
                "type": "SQL_INJECTION",
                "severity": "HIGH",
                "source_ip": "10.10.10.60",
                "timestamp": timestamp
            },
            {
                "type": "XSS",
                "severity": "HIGH",
                "source_ip": "10.10.10.60",
                "timestamp": timestamp + timedelta(minutes=10)
            }
        ]

        correlated = correlate_alerts(alerts)

        self.assertEqual(len(correlated), 0)


if __name__ == "__main__":
    unittest.main()