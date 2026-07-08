"""Unit tests for scanner/scanner.py compliance scoring and region discovery."""
from unittest.mock import patch, MagicMock

from scanner import scanner
from scanner.scanner import compute_summary, _get_regions
from scanner.models import Finding, Severity, Status


def _f(status: Status) -> Finding:
    return Finding(
        check_id="X-001",
        title="test",
        resource="res",
        service="S3",
        severity=Severity.LOW,
        status=status,
        region="us-east-1",
        remediation="fix it",
    )


class TestComputeSummary:
    def test_error_findings_excluded_from_score(self):
        findings = [_f(Status.PASS), _f(Status.PASS), _f(Status.FAIL), _f(Status.ERROR)]
        summary = compute_summary(findings)
        assert summary["total"] == 4
        assert summary["passed"] == 2
        assert summary["failed"] == 1
        assert summary["errored"] == 1
        # 2 passed / (2 passed + 1 failed) = 66.7%, ERROR excluded from denominator
        assert summary["score"] == 66.7

    def test_all_pass_is_100(self):
        summary = compute_summary([_f(Status.PASS), _f(Status.PASS)])
        assert summary["score"] == 100.0

    def test_all_fail_is_zero(self):
        summary = compute_summary([_f(Status.FAIL), _f(Status.FAIL)])
        assert summary["score"] == 0.0

    def test_only_errors_scores_100(self):
        # Nothing evaluable → score defaults to 100 rather than dividing by zero
        summary = compute_summary([_f(Status.ERROR), _f(Status.ERROR)])
        assert summary["score"] == 100.0
        assert summary["errored"] == 2

    def test_empty_findings_scores_100(self):
        summary = compute_summary([])
        assert summary["score"] == 100.0
        assert summary["total"] == 0


class TestGetRegions:
    def test_discovers_enabled_regions(self, monkeypatch):
        monkeypatch.delenv("SCAN_REGIONS", raising=False)
        ec2 = MagicMock()
        ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-west-2"}, {"RegionName": "eu-west-1"}]
        }
        with patch.object(scanner.boto3, "client", return_value=ec2):
            regions = _get_regions("us-east-1")
        assert regions == ["eu-west-1", "us-west-2"]  # sorted

    def test_scan_regions_override_wins(self, monkeypatch):
        monkeypatch.setenv("SCAN_REGIONS", "us-east-1, ap-south-1 ,")
        # describe_regions must not even be called when override is set
        ec2 = MagicMock()
        with patch.object(scanner.boto3, "client", return_value=ec2):
            regions = _get_regions("us-east-1")
        assert regions == ["us-east-1", "ap-south-1"]
        ec2.describe_regions.assert_not_called()

    def test_falls_back_to_home_region_on_error(self, monkeypatch):
        monkeypatch.delenv("SCAN_REGIONS", raising=False)
        ec2 = MagicMock()
        ec2.describe_regions.side_effect = Exception("AccessDenied")
        with patch.object(scanner.boto3, "client", return_value=ec2):
            regions = _get_regions("us-east-1")
        assert regions == ["us-east-1"]
