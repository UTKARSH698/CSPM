"""
Unit tests for scanner/checks/cloudtrail_checks.py
Uses moto to mock CloudTrail and S3 API calls.
"""
import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock
from scanner.checks import cloudtrail_checks
from scanner.models import Status, Severity


REGION = "us-east-1"


def _make_trail(ct, s3, name: str = "test-trail", multi_region: bool = True,
                log_validation: bool = True, cw_logs_arn: str = "arn:aws:logs:us-east-1:123:log-group/ct") -> dict:
    """Create a mock S3 bucket and CloudTrail trail."""
    bucket = f"trail-bucket-{name}"
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    kwargs = {
        "Name": name,
        "S3BucketName": bucket,
        "IsMultiRegionTrail": multi_region,
        "EnableLogFileValidation": log_validation,
    }
    if cw_logs_arn:
        kwargs["CloudWatchLogsLogGroupArn"] = cw_logs_arn
        kwargs["CloudWatchLogsRoleArn"] = "arn:aws:iam::123:role/ct-cw-role"
    trail = ct.create_trail(**kwargs)
    ct.start_logging(Name=name)
    return trail


# ── CT-001: Trail Exists ──────────────────────────────────────────────────────

class TestCheckTrailExists:
    def test_pass_when_trails_exist(self):
        trails = [{"Name": "my-trail"}]
        finding = cloudtrail_checks._check_trail_exists(trails, REGION)
        assert finding.status == Status.PASS

    def test_fail_when_no_trails(self):
        finding = cloudtrail_checks._check_trail_exists([], REGION)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL


# ── CT-002: Multi-Region ──────────────────────────────────────────────────────

class TestCheckMultiRegion:
    def test_pass_when_multi_region(self):
        trail = {"Name": "my-trail", "IsMultiRegionTrail": True}
        finding = cloudtrail_checks._check_multi_region(trail, REGION)
        assert finding.status == Status.PASS

    def test_fail_when_single_region(self):
        trail = {"Name": "my-trail", "IsMultiRegionTrail": False}
        finding = cloudtrail_checks._check_multi_region(trail, REGION)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.HIGH

    def test_fail_when_key_missing(self):
        trail = {"Name": "my-trail"}
        finding = cloudtrail_checks._check_multi_region(trail, REGION)
        assert finding.status == Status.FAIL


# ── CT-003: Log Validation ────────────────────────────────────────────────────

class TestCheckLogValidation:
    def test_pass_when_enabled(self):
        trail = {"Name": "my-trail", "LogFileValidationEnabled": True}
        finding = cloudtrail_checks._check_log_validation(trail, REGION)
        assert finding.status == Status.PASS

    def test_fail_when_disabled(self):
        trail = {"Name": "my-trail", "LogFileValidationEnabled": False}
        finding = cloudtrail_checks._check_log_validation(trail, REGION)
        assert finding.status == Status.FAIL

    def test_fail_when_key_missing(self):
        trail = {"Name": "my-trail"}
        finding = cloudtrail_checks._check_log_validation(trail, REGION)
        assert finding.status == Status.FAIL


# ── CT-004: CloudWatch Logs ───────────────────────────────────────────────────

class TestCheckCloudwatchLogs:
    def test_pass_when_cw_logs_configured(self):
        trail = {
            "Name": "my-trail",
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123:log-group/ct",
        }
        finding = cloudtrail_checks._check_cloudwatch_logs(trail, REGION)
        assert finding.status == Status.PASS

    def test_fail_when_no_cw_logs(self):
        trail = {"Name": "my-trail"}
        finding = cloudtrail_checks._check_cloudwatch_logs(trail, REGION)
        assert finding.status == Status.FAIL

    def test_fail_when_empty_arn(self):
        trail = {"Name": "my-trail", "CloudWatchLogsLogGroupArn": ""}
        finding = cloudtrail_checks._check_cloudwatch_logs(trail, REGION)
        assert finding.status == Status.FAIL


# ── CT-005: S3 Bucket Public Access ──────────────────────────────────────────

class TestCheckS3PublicAccess:
    @mock_aws
    def test_pass_when_bucket_has_block_public_access(self):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="secure-trail-bucket")
        s3.put_public_access_block(
            Bucket="secure-trail-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        trail = {"Name": "my-trail", "S3BucketName": "secure-trail-bucket"}
        finding = cloudtrail_checks._check_s3_public_access(trail, REGION)
        assert finding.status == Status.PASS

    @mock_aws
    def test_fail_when_bucket_has_no_block(self):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="open-trail-bucket")
        trail = {"Name": "my-trail", "S3BucketName": "open-trail-bucket"}
        finding = cloudtrail_checks._check_s3_public_access(trail, REGION)
        assert finding.status == Status.FAIL

    def test_fail_when_no_bucket_configured(self):
        trail = {"Name": "my-trail", "S3BucketName": ""}
        finding = cloudtrail_checks._check_s3_public_access(trail, REGION)
        assert finding.status == Status.FAIL


# ── CT-006: Trail Logging Active ──────────────────────────────────────────────

class TestCheckTrailLogging:
    def test_pass_when_logging_active(self):
        ct = MagicMock()
        ct.get_trail_status.return_value = {"IsLogging": True}
        trail = {"Name": "my-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail"}
        findings = cloudtrail_checks._check_trail_logging(ct, trail, REGION)
        assert findings[0].status == Status.PASS

    def test_fail_when_logging_stopped(self):
        ct = MagicMock()
        ct.get_trail_status.return_value = {"IsLogging": False}
        trail = {"Name": "my-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail"}
        findings = cloudtrail_checks._check_trail_logging(ct, trail, REGION)
        assert findings[0].status == Status.FAIL
        assert findings[0].severity == Severity.CRITICAL

    def test_fail_on_exception(self):
        ct = MagicMock()
        ct.get_trail_status.side_effect = Exception("Access denied")
        trail = {"Name": "my-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail"}
        findings = cloudtrail_checks._check_trail_logging(ct, trail, REGION)
        assert findings[0].status == Status.FAIL
