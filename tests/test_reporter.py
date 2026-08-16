import unittest
from datetime import datetime
from io import StringIO
from unittest.mock import patch

from src.reporter import print_summary


class TestReporter(unittest.TestCase):

    def test_print_summary(self):
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
                "timestamp": timestamp
            },
            {
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": "10.10.10.50",
                "timestamp": timestamp
            },
            {
                "type": "ATTACK_CAMPAIGN",
                "severity": "CRITICAL",
                "source_ip": "10.10.10.60",
                "timestamp": timestamp
            }
        ]

        with patch("sys.stdout", new=StringIO()) as fake_output:
            print_summary(alerts)

            output = fake_output.getvalue()

        self.assertIn("Total alerts : 4", output)
        self.assertIn("Critical     : 1", output)
        self.assertIn("High         : 3", output)

        self.assertIn("SQL_INJECTION", output)
        self.assertIn("XSS", output)
        self.assertIn("BRUTE_FORCE", output)
        self.assertIn("ATTACK_CAMPAIGN", output)

        self.assertIn("10.10.10.60", output)
        self.assertIn("10.10.10.50", output)


if __name__ == "__main__":
    unittest.main()