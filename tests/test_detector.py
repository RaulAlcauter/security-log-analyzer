import unittest

from datetime import datetime, timedelta

from src.detectors import (
    detect_brute_force,
    detect_sql_injection,
    detect_xss,
    detect_path_traversal,
    normalize_url
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

    def test_brute_force_does_not_mix_ips(self):
        base_time = datetime(2026, 8, 10, 10, 0, 0)

        events = []

        for i in range(6):
            events.append({
                "type": "AUTH",
                "event": "LOGIN_FAILURE",
                "source_ip": "10.10.10.1",
                "timestamp": base_time + timedelta(seconds=i)
            })

        for i in range(6):
            events.append({
                "type": "AUTH",
                "event": "LOGIN_FAILURE",
                "source_ip": "10.10.10.2",
                "timestamp": base_time + timedelta(seconds=i)
            })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_brute_force_ignores_successful_logins(self):
        base_time = datetime(2026, 8, 10, 10, 0, 0)

        events = []

        for i in range(9):
            events.append({
                "type": "AUTH",
                "event": "LOGIN_FAILURE",
                "source_ip": "10.10.10.50",
                "timestamp": base_time + timedelta(seconds=i)
            })

        events.append({
            "type": "AUTH",
            "event": "LOGIN_SUCCESS",
            "source_ip": "10.10.10.50",
            "timestamp": base_time + timedelta(seconds=9)
        })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_brute_force_handles_unsorted_events(self):
        base_time = datetime(2026, 8, 10, 10, 0, 0)

        events = []

        for i in range(10):
            events.append({
                "type": "AUTH",
                "event": "LOGIN_FAILURE",
                "source_ip": "10.10.10.50",
                "timestamp": base_time + timedelta(seconds=i)
            })

        events.reverse()

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)

    def test_sql_injection_case_insensitive(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.50",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/products?id=1%27%20oR%20%271%27%3D%271",
        }

        alerts = detect_sql_injection([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "SQL_INJECTION")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.50")

    def test_sql_injection_double_url_encoded(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.51",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/products?id=1%2527%2520OR%2520%25271%2527%253D%25271",
        }

        alerts = detect_sql_injection([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "SQL_INJECTION")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.51")

    def test_sql_injection_triple_url_encoded(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.52",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/products?id=1%252527%252520OR%252520%2525271%252527%25253D%2525271",
        }

        alerts = detect_sql_injection([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "SQL_INJECTION")

    def test_sql_injection_four_url_encoded(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.53",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/products?id=1%25252527%25252520OR%25252520%252525271%25252527%2525253D%252525271",
        }

        alerts = detect_sql_injection([event])

        self.assertEqual(len(alerts), 0)

    def test_normalize_url_single_encoding(self):
        value = "%27"

        result = normalize_url(value)

        self.assertEqual(result, "'")


    def test_normalize_url_double_encoding(self):
        value = "%2527"

        result = normalize_url(value)

        self.assertEqual(result, "'")


    def test_normalize_url_triple_encoding(self):
        value = "%252527"

        result = normalize_url(value)

        self.assertEqual(result, "'")


    def test_normalize_url_respects_max_decodes(self):
        value = "%25252527"

        result = normalize_url(value)

        self.assertEqual(result, "%27")

    def test_xss_case_insensitive(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.54",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/search?q=%3CSCRIPT%3Ealert(1)%3C%2FSCRIPT%3E",
        }

        alerts = detect_xss([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "XSS")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.54")

    def test_xss_onerror_with_spaces_and_case_variation(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.55",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/profile?name=%3CIMG%20SRC%3Dx%20ONERROR%20%3D%20alert(1)%3E",
        }

        alerts = detect_xss([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "XSS")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.55")

    def test_xss_onerror_with_html_comment(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.56",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/profile?name=%3Cimg%20src%3Dx%20onerror%2F%2A%2A%2F%3Dalert(1)%3E",
        }

        alerts = detect_xss([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "XSS")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.56")

    def test_path_traversal_windows_style(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.57",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/download?file=..%5C..%5C..%5C..%5CWindows%5CSystem32",
        }

        alerts = detect_path_traversal([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "PATH_TRAVERSAL")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.57")

    def test_path_traversal_mixed_encoding(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.58",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/download?file=..%2F..%2F..%2Fetc/passwd",
        }

        alerts = detect_path_traversal([event])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "PATH_TRAVERSAL")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.58")

    def test_sql_injection_does_not_flag_legitimate_query(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.59",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/products?id=123&sort=price",
        }

        alerts = detect_sql_injection([event])

        self.assertEqual(len(alerts), 0)

    def test_xss_does_not_flag_legitimate_search(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.60",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/search?q=hello+world",
        }

        alerts = detect_xss([event])

        self.assertEqual(len(alerts), 0)

    def test_path_traversal_does_not_flag_legitimate_file(self):
        event = {
            "type": "WEB",
            "source_ip": "192.168.1.61",
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "path": "/download?file=report.pdf",
        }

        alerts = detect_path_traversal([event])

        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()