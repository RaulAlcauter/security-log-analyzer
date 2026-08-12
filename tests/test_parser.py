import unittest

from src.parser import parse_access_log, parse_auth_log

class TestParser(unittest.TestCase):

    def test_parse_access_log(self):
        line = "2026-08-10T10:15:01 192.168.1.20 GET /products 200"

        event = parse_access_log(line)

        self.assertEqual(event["type"], "WEB")
        self.assertEqual(event["source_ip"], "192.168.1.20")
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["path"], "/products")
        self.assertEqual(event["status"], 200)

    def test_parse_auth_log(self):
        line = "2026-08-10T10:05:12 192.168.1.21 LOGIN_FAILURE admin"

        event = parse_auth_log(line)

        self.assertEqual(event["type"], "AUTH")
        self.assertEqual(event["source_ip"], "192.168.1.21")
        self.assertEqual(event["event"], "LOGIN_FAILURE")
        self.assertEqual(event["username"], "admin")


if __name__ == "__main__":
    unittest.main()