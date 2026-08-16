import unittest

from src.mitre import get_mitre_mapping, add_mitre_mapping


class TestMitre(unittest.TestCase):

    def test_brute_force_mapping(self):
        mapping = get_mitre_mapping("BRUTE_FORCE")

        self.assertIsNotNone(mapping)
        self.assertEqual(mapping["technique_id"], "T1110")
        self.assertEqual(mapping["technique"], "Brute Force")
        self.assertEqual(mapping["tactic"], "Credential Access")
        self.assertEqual(mapping["confidence"], "HIGH")

    def test_sql_injection_mapping(self):
        mapping = get_mitre_mapping("SQL_INJECTION")

        self.assertIsNotNone(mapping)
        self.assertEqual(mapping["technique_id"], "T1190")
        self.assertEqual(mapping["confidence"], "MEDIUM")

    def test_xss_mapping(self):
        mapping = get_mitre_mapping("XSS")

        self.assertIsNotNone(mapping)
        self.assertEqual(mapping["technique_id"], "T1189")
        self.assertEqual(mapping["confidence"], "LOW")

    def test_unknown_alert_has_no_mapping(self):
        mapping = get_mitre_mapping("UNKNOWN")

        self.assertIsNone(mapping)

    def test_add_mitre_mapping(self):
        alert = {
            "type": "BRUTE_FORCE",
            "severity": "HIGH"
        }

        add_mitre_mapping(alert)

        self.assertIn("mitre", alert)
        self.assertEqual(
            alert["mitre"]["technique_id"],
            "T1110"
        )


if __name__ == "__main__":
    unittest.main()