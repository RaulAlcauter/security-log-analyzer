import unittest

from datetime import datetime

from src.detectors import (
    detect_brute_force,
    detect_sql_injection,
    detect_xss,
    detect_path_traversal
)


class TestDetectors(unittest.TestCase):

    def test_brute_force_detected(self):
        events = []

        for i in range(10):
            events.append({
                "type": "AUTH",
                "timestamp": datetime(2026, 8, 10, 10, 0, i),
                "source_ip": "10.10.10.50",
                "event": "LOGIN_FAILURE",
                "username": "admin"
            })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "BRUTE_FORCE")

    def test_sql_injection_detected(self):
        events = [
            {
                "type": "WEB",
                "timestamp": datetime(2026, 8, 10, 10, 0, 0),
                "source_ip": "192.168.1.31",
                "method": "GET",
                "path": "/products?id=1%27%20OR%20%271%27%3D%271",
                "status": 200
            }
        ]

        alerts = detect_sql_injection(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "SQL_INJECTION")

    def test_xss_detected(self):
        events = [
            {
                "type": "WEB",
                "timestamp": datetime(2026, 8, 10, 10, 0, 0),
                "source_ip": "192.168.1.35",
                "method": "GET",
                "path": "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "status": 200
            }
        ]

        alerts = detect_xss(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "XSS")

    def test_path_traversal_detected(self):
        events = [
            {
                "type": "WEB",
                "timestamp": datetime(2026, 8, 10, 10, 0, 0),
                "source_ip": "192.168.1.40",
                "method": "GET",
                "path": "/download?file=..%2F..%2F..%2Fetc%2Fpasswd",
                "status": 403
            }
        ]

        alerts = detect_path_traversal(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "PATH_TRAVERSAL")

    def test_brute_force_not_detected_below_threshold(self):
        events = []

        for i in range(9):
            events.append({
                "type": "AUTH",
                "timestamp": datetime(2026, 8, 10, 10, 0, i),
                "source_ip": "10.10.10.50",
                "event": "LOGIN_FAILURE",
                "username": "admin"
            })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_brute_force_not_detected_outside_time_window(self):
        events = []

        for i in range(10):
            events.append({
                "type": "AUTH",
                "timestamp": datetime(2026, 8, 10, 10 + i, 0, 0),
                "source_ip": "10.10.10.50",
                "event": "LOGIN_FAILURE",
                "username": "admin"
            })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_normal_web_request_not_detected_as_sql_injection(self):
        events = [
            {
                "type": "WEB",
                "timestamp": datetime(2026, 8, 10, 10, 0, 0),
                "source_ip": "192.168.1.30",
                "method": "GET",
                "path": "/products?id=42",
                "status": 200
            }
        ]

        alerts = detect_sql_injection(events)

        self.assertEqual(len(alerts), 0)

    def test_normal_web_request_not_detected_as_xss(self):
        events = [
            {
                "type": "WEB",
                "timestamp": datetime(2026, 8, 10, 10, 0, 0),
                "source_ip": "192.168.1.37",
                "method": "GET",
                "path": "/search?q=hello+world",
                "status": 200
            }
        ]

        alerts = detect_xss(events)

        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()