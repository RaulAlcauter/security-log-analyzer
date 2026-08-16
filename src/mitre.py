MITRE_MAPPINGS = {
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "HIGH",
        "rationale": (
            "Multiple authentication failures from the same source "
            "within a short time window are consistent with brute-force activity."
        )
    },

    "SQL_INJECTION": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "confidence": "MEDIUM",
        "rationale": (
            "The detected SQL injection payload is consistent with exploitation "
            "of a web application. The mapping assumes the targeted application "
            "is publicly accessible."
        )
    },

    "PATH_TRAVERSAL": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "confidence": "MEDIUM",
        "rationale": (
            "The detected path traversal payload is consistent with exploitation "
            "of a web application. The mapping assumes the targeted application "
            "is publicly accessible."
        )
    },

    "XSS": {
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "tactic": "Initial Access",
        "confidence": "LOW",
        "rationale": (
            "The detected XSS payload may be relevant to drive-by compromise "
            "when malicious scripts are delivered to and executed by a victim's browser."
        )
    }
}


def get_mitre_mapping(alert_type):
    return MITRE_MAPPINGS.get(alert_type)

def add_mitre_mapping(alert):
    mapping = get_mitre_mapping(alert["type"])

    if mapping:
        alert["mitre"] = mapping.copy()

    return alert