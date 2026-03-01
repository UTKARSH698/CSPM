"""Unit tests for the Finding model."""
import pytest
from scanner.models import Finding, Severity, Status


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        check_id="S3-001",
        title="Test finding",
        resource="my-bucket",
        service="S3",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        region="us-east-1",
        remediation="Fix it.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestFinding:
    def test_to_dict_has_required_keys(self):
        f = _make_finding()
        d = f.to_dict()
        assert set(d.keys()) == {
            "check_id", "title", "resource", "service",
            "severity", "status", "region", "remediation", "timestamp",
        }

    def test_severity_serialized_as_string(self):
        f = _make_finding(severity=Severity.CRITICAL)
        assert f.to_dict()["severity"] == "CRITICAL"

    def test_status_serialized_as_string(self):
        f = _make_finding(status=Status.PASS)
        assert f.to_dict()["status"] == "PASS"

    def test_timestamp_is_set_automatically(self):
        f = _make_finding()
        assert f.timestamp != ""
        assert "T" in f.timestamp       # ISO format check

    def test_fail_finding(self):
        f = _make_finding(status=Status.FAIL)
        assert f.status == Status.FAIL

    def test_pass_finding(self):
        f = _make_finding(status=Status.PASS)
        assert f.status == Status.PASS

    def test_all_severities(self):
        for sev in Severity:
            f = _make_finding(severity=sev)
            assert f.to_dict()["severity"] == sev.value
