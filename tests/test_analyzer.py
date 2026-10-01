import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from analyzer import detect_threats


def test_repeated_failed_logins_are_high():
    log = """
Failed password for root from 198.51.100.25
Failed password for root from 198.51.100.25
Failed password for root from 198.51.100.25
Failed password for root from 198.51.100.25
Failed password for root from 198.51.100.25
"""

    findings = detect_threats(log)

    assert any(
        finding["severity"] == "High"
        and finding["category"] == "Repeated Authentication Failures"
        for finding in findings
    )


def test_web_attack_is_detected():
    log = """
GET /../../etc/passwd HTTP/1.1 404
"""

    findings = detect_threats(log)

    assert any(
        finding["severity"] == "High"
        and finding["category"] == "Possible Web Attack"
        for finding in findings
    )


def test_normal_login_is_low():
    log = """
Accepted password for admin from 192.0.2.10 port 50001 ssh2
"""

    findings = detect_threats(log)

    assert findings
    assert all(
        finding["severity"] == "Low"
        for finding in findings
    )


def test_sudo_activity_is_detected():
    log = """
sudo: user1 : TTY=pts/0 ; COMMAND=/usr/bin/whoami
"""

    findings = detect_threats(log)

    assert any(
        finding["category"] == "Privilege Escalation"
        for finding in findings
    )
