# Security Log Analyzer

A Python-based security log analysis tool focused on defensive security and detection engineering.

The project parses web access and authentication logs, detects suspicious activity, correlates related alerts, assigns risk scores, and enriches detections with MITRE ATT&CK information.

This project was built as a learning project to develop practical Blue Team and detection engineering skills.

---

## Features

- Web access log parsing
- Authentication log parsing
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- Path Traversal detection
- Brute-force detection
- Alert correlation
- Risk scoring
- MITRE ATT&CK enrichment
- URL normalization
- Detection of encoded and double/triple-encoded payloads
- False-positive testing
- Human-readable alert reporting
- Alert summary reporting
- JSON reporting
- Configurable detection thresholds
- Automated test suite

---

## Architecture

The analyzer follows a modular detection pipeline:

    LOGS
      |
      v
    PARSER
      |
      v
    DETECTION ENGINE
      |
      +-- SQL Injection
      +-- XSS
      +-- Path Traversal
      +-- Brute Force
      |
      v
    MITRE ATT&CK ENRICHMENT
      |
      v
    ALERT CORRELATION
      |
      v
    RISK SCORING
      |
      v
    REPORTER

Each component has a specific responsibility:

- `parser.py` — parses access and authentication logs.
- `detectors.py` — detects suspicious activity.
- `correlator.py` — correlates multiple alerts from the same source.
- `risk.py` — calculates campaign risk scores and severity.
- `mitre.py` — enriches alerts with MITRE ATT&CK mappings.
- `reporter.py` — generates human-readable and JSON output.
- `config.py` — loads detection configuration.
- `analyzer.py` — orchestrates the complete analysis pipeline.

## Detection Engine

### SQL Injection

The analyzer detects several common SQL injection patterns, including:

- `UNION SELECT`
- Boolean-based injection
- SQL comments
- `SLEEP()`
- `BENCHMARK()`

Example:

    /products?id=1' OR '1'='1'

The analyzer performs bounded URL normalization before applying detection patterns.

This allows it to detect payloads using URL encoding and multiple layers of URL encoding.

---

### Cross-Site Scripting (XSS)

The analyzer detects common XSS indicators such as:

- `<script>`
- `javascript:`
- `<iframe>`
- `<object>`
- `onerror=`
- `onload=`

Example:

    <img src=x onerror=alert(1)>

XSS input receives additional normalization for HTML comments, allowing the detector to handle variations such as:

    <img src=x onerror/**/=alert(1)>

---

### Path Traversal

The analyzer detects common path traversal patterns, including Unix and Windows-style paths.

Examples:

    ../../../../etc/passwd

    ..\..\..\..\Windows\System32

URL-encoded and mixed-encoding variants are also tested.

---

### Brute Force

Brute-force detection identifies repeated authentication failures originating from the same source IP within a configurable time window.

For example:

    10 failed login attempts
    within 60 seconds
            |
            v
       BRUTE_FORCE

The threshold and time window are configurable through `config/rules.json`.

## Alert Correlation

Individual alerts can be correlated when multiple suspicious activities originate from the same source.

For example:

    10.10.10.60
         |
         +---- SQL_INJECTION
         |
         +---- XSS
         |
         v
    ATTACK_CAMPAIGN

This allows the analyzer to identify activity that becomes more significant when multiple detections are considered together.

Correlated campaigns include:

- Source IP
- First seen timestamp
- Last seen timestamp
- Campaign duration
- Risk score
- Related alerts
- Campaign severity

---

## Risk Scoring

Correlated activity receives a risk score based on the severity and combination of related alerts.

The resulting score is then used to determine the severity of the campaign.

Example:

    SQL_INJECTION  -> HIGH
    XSS            -> HIGH
                         |
                         v
                   Risk Score: 6
                         |
                         v
                  CRITICAL CAMPAIGN

The risk scoring logic is implemented separately from the detection engine so that detection and prioritization remain independent responsibilities.

---

## MITRE ATT&CK

Detected activity can be enriched with MITRE ATT&CK information.

Example:

    BRUTE_FORCE
         |
         v
    T1110 - Brute Force
         |
         v
    Credential Access

Current mappings include:

| Alert Type | Technique | Tactic | Confidence |
|---|---|---|---|
| Brute Force | T1110 - Brute Force | Credential Access | HIGH |
| SQL Injection | T1190 - Exploit Public-Facing Application | Initial Access | MEDIUM |
| Path Traversal | T1190 - Exploit Public-Facing Application | Initial Access | MEDIUM |
| XSS | T1189 - Drive-by Compromise | Initial Access | LOW |

Confidence levels are included because log evidence does not always prove that a particular ATT&CK technique was successfully executed.

For example, detecting an XSS payload does not by itself prove that a victim executed the malicious script.

## URL Normalization and Evasion Handling

One of the goals of the project is to test detection rules against different representations of the same payload.

The analyzer performs bounded URL decoding.

For example:

    %27

can be decoded into:

    '

Double encoding:

    %2527

can be normalized into:

    '

Triple encoding is also supported.

The normalizer intentionally limits the number of decoding passes to three:

    max_decodes = 3

This prevents unbounded normalization of attacker-controlled input.

During development, this testing uncovered a real false negative in the SQL injection detector caused by double URL encoding. The normalization logic was then improved and regression tests were added.

---

## False-Positive Testing

The test suite does not only check whether attacks are detected.

It also verifies that legitimate requests are not incorrectly classified as attacks.

Examples include:

    /products?id=123&sort=price

    /search?q=hello+world

    /download?file=report.pdf

These requests should not generate SQL Injection, XSS, or Path Traversal alerts.

This is important because overly aggressive detection rules can create excessive noise for security analysts.

---

## Configuration

Detection thresholds are configured through:

`config/rules.json`

Example:

    {
        "brute_force": {
            "threshold": 10,
            "window_seconds": 60
        }
    }

This allows detection behavior to be modified without changing the detector implementation.

---

## Project Structure

    security-log-analyzer/
    |
    ├── README.md
    |
    ├── config/
    │   └── rules.json
    |
    ├── logs/
    │   ├── access.log
    │   └── auth.log
    |
    ├── src/
    │   ├── __init__.py
    │   ├── analyzer.py
    │   ├── config.py
    │   ├── correlator.py
    │   ├── detectors.py
    │   ├── mitre.py
    │   ├── parser.py
    │   ├── reporter.py
    │   └── risk.py
    |
    └── tests/
        ├── __init__.py
        ├── test_correlator.py
        ├── test_detector.py
        ├── test_mitre.py
        ├── test_parser.py
        ├── test_reporter.py
        └── test_risk.py

## Usage

Run the analyzer with the default configuration:

    python3 src/analyzer.py

The analyzer will parse the configured access and authentication logs and display the detected alerts.

### Summary Mode

A condensed summary can be displayed using:

    python3 src/analyzer.py --summary

Example:

    ============================================================
    SECURITY SUMMARY
    ============================================================

    Total alerts : 10
    Critical     : 1
    High         : 9
    Medium       : 0
    Low          : 0

    By type:
      SQL_INJECTION       : 3
      XSS                 : 3
      PATH_TRAVERSAL      : 2
      BRUTE_FORCE         : 1
      ATTACK_CAMPAIGN     : 1

    Top source IPs:
      10.10.10.60         : 3
      192.168.1.31        : 1
      192.168.1.33        : 1
      192.168.1.35        : 1
      192.168.1.36        : 1
    ============================================================

---

## Example Alert Output

A normal detection can look like:

    [HIGH] SQL_INJECTION

    Source IP : 192.168.1.31
    Endpoint  : /products?id=1%27%20OR%20%271%27%3D%271
    Pattern   : '\s*or\s*'

    MITRE ATT&CK:
      Technique : T1190 - Exploit Public-Facing Application
      Tactic    : Initial Access
      Confidence: MEDIUM

A correlated campaign can look like:

    [CRITICAL] ATTACK_CAMPAIGN

    Source IP : 10.10.10.60
    First seen: 2026-08-10 10:25:05
    Last seen : 2026-08-10 10:25:10
    Duration  : 5.0 seconds
    Risk score: 6

    Related alerts:

      [HIGH] SQL_INJECTION
        Endpoint: /products?id=1%27%20OR%20%271%27%3D%271

      [HIGH] XSS
        Endpoint: /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E

---

## Testing

The project currently includes **42 automated tests** covering:

- Log parsing
- SQL Injection detection
- XSS detection
- Path Traversal detection
- Brute-force detection
- Alert correlation
- Risk scoring
- MITRE ATT&CK mappings
- Reporting
- Alert summaries
- URL normalization
- Encoded payload handling
- Double and triple URL encoding
- False-positive cases
- Unordered authentication events
- Multiple source IP handling

Run the complete test suite with:

    python3 -m unittest discover

Expected result:

    Ran 42 tests

    OK

## Limitations

This project is intended for educational purposes and detection-engineering practice. It is not a production SIEM and does not replace a full security monitoring platform.

Detection rules are heuristic and may produce false positives or false negatives.

URL normalization is intentionally bounded to a maximum of three decoding passes.

MITRE ATT&CK mappings represent potential mappings based on the available log evidence and include confidence levels where appropriate.

The project currently focuses on a limited set of web and authentication attack patterns and does not attempt to provide comprehensive coverage of real-world attack techniques.

---

## Future Improvements

Possible future improvements include:

- Additional authentication attack detections
- More advanced correlation rules
- Detection of normalization and encoding anomalies
- Additional MITRE ATT&CK mappings
- More log formats
- Improved JSON output
- Additional configurable detection rules
- Dashboard or visualization layer
- More extensive performance testing
- Integration with external SIEM platforms

---

## Learning Goals

This project was built to develop practical knowledge in:

- Blue Team fundamentals
- Detection engineering
- Log analysis
- Security event normalization
- Alert correlation
- Risk-based prioritization
- MITRE ATT&CK
- Python development
- Unit testing
- Defensive security automation

---

## Disclaimer

This project is intended for defensive security research, learning, and detection-engineering practice.

The logs included in the repository are synthetic examples created for testing and demonstration purposes.

## Conclusion

Security Log Analyzer demonstrates a modular approach to defensive security monitoring and detection engineering.

The project combines log parsing, heuristic detection, alert correlation, risk-based prioritization, MITRE ATT&CK enrichment, configurable rules, and automated testing into a single Python-based workflow.

The implementation is intentionally focused on learning and experimentation rather than production-scale security monitoring. Its main objective is to provide a practical environment for understanding how offensive techniques can be translated into defensive detections and investigated from a Blue Team perspective.