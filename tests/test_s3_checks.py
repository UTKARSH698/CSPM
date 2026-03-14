"""
Unit tests for scanner/checks/s3_checks.py
Uses moto to mock AWS S3 API calls — no real AWS credentials needed.
"""
import boto3
import pytest
from moto import mock_aws
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from scanner.checks import s3_checks
from scanner.models import Status, Severity


REGION = "us-east-1"


def _s3_client():
    return boto3.client("s3", region_name=REGION)


def _make_bucket(s3, name: str) -> str:
    s3.create_bucket(Bucket=name)
    return name


# ── S3-001: Block Public Access ───────────────────────────────────────────────

class TestCheckPublicAccess:
    @mock_aws
    def test_pass_when_all_four_settings_enabled(self):
        s3 = _s3_client()
        _make_bucket(s3, "secure-bucket")
        s3.put_public_access_block(
            Bucket="secure-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        finding = s3_checks._check_public_access(s3, "secure-bucket", REGION)
        assert finding.status == Status.PASS

    @mock_aws
    def test_fail_when_one_setting_disabled(self):
        s3 = _s3_client()
        _make_bucket(s3, "partial-block")
        s3.put_public_access_block(
            Bucket="partial-block",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            },
        )
        finding = s3_checks._check_public_access(s3, "partial-block", REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_fail_when_no_public_access_block_configured(self):
        # moto returns all-False config when no block is set → FAIL
        s3 = _s3_client()
        _make_bucket(s3, "no-block-bucket")
        finding = s3_checks._check_public_access(s3, "no-block-bucket", REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_critical_severity(self):
        s3 = _s3_client()
        _make_bucket(s3, "sev-bucket")
        finding = s3_checks._check_public_access(s3, "sev-bucket", REGION)
        assert finding.severity == Severity.CRITICAL
        assert finding.check_id == "S3-001"


# ── S3-002: Versioning ────────────────────────────────────────────────────────

class TestCheckVersioning:
    @mock_aws
    def test_pass_when_versioning_enabled(self):
        s3 = _s3_client()
        _make_bucket(s3, "versioned-bucket")
        s3.put_bucket_versioning(
            Bucket="versioned-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )
        finding = s3_checks._check_versioning(s3, "versioned-bucket", REGION)
        assert finding.status == Status.PASS

    @mock_aws
    def test_fail_when_versioning_not_configured(self):
        s3 = _s3_client()
        _make_bucket(s3, "no-versioning")
        finding = s3_checks._check_versioning(s3, "no-versioning", REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_fail_when_versioning_suspended(self):
        s3 = _s3_client()
        _make_bucket(s3, "suspended-bucket")
        s3.put_bucket_versioning(
            Bucket="suspended-bucket",
            VersioningConfiguration={"Status": "Suspended"},
        )
        finding = s3_checks._check_versioning(s3, "suspended-bucket", REGION)
        assert finding.status == Status.FAIL

    def test_fail_on_exception(self):
        s3 = MagicMock()
        s3.get_bucket_versioning.side_effect = Exception("error")
        finding = s3_checks._check_versioning(s3, "some-bucket", REGION)
        assert finding.status == Status.FAIL

    def test_low_severity(self):
        s3 = MagicMock()
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        finding = s3_checks._check_versioning(s3, "some-bucket", REGION)
        assert finding.severity == Severity.LOW


# ── S3-003: Logging ───────────────────────────────────────────────────────────

class TestCheckLogging:
    def test_pass_when_logging_enabled(self):
        s3 = MagicMock()
        s3.get_bucket_logging.return_value = {
            "LoggingEnabled": {"TargetBucket": "log-target", "TargetPrefix": "logs/"}
        }
        finding = s3_checks._check_logging(s3, "logged-bucket", REGION)
        assert finding.status == Status.PASS

    @mock_aws
    def test_fail_when_no_logging(self):
        s3 = _s3_client()
        _make_bucket(s3, "unlogged-bucket")
        finding = s3_checks._check_logging(s3, "unlogged-bucket", REGION)
        assert finding.status == Status.FAIL

    def test_fail_on_exception(self):
        s3 = MagicMock()
        s3.get_bucket_logging.side_effect = Exception("error")
        finding = s3_checks._check_logging(s3, "some-bucket", REGION)
        assert finding.status == Status.FAIL


# ── S3-004: Encryption ────────────────────────────────────────────────────────

class TestCheckEncryption:
    @mock_aws
    def test_pass_when_encryption_enabled(self):
        s3 = _s3_client()
        _make_bucket(s3, "encrypted-bucket")
        s3.put_bucket_encryption(
            Bucket="encrypted-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        finding = s3_checks._check_encryption(s3, "encrypted-bucket", REGION)
        assert finding.status == Status.PASS

    def test_fail_when_no_encryption(self):
        s3 = MagicMock()
        err = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            "GetBucketEncryption",
        )
        s3.get_bucket_encryption.side_effect = err
        s3.exceptions.ClientError = ClientError
        finding = s3_checks._check_encryption(s3, "plain-bucket", REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_fail_when_no_encryption_configured(self):
        s3 = _s3_client()
        _make_bucket(s3, "plain-bucket")
        finding = s3_checks._check_encryption(s3, "plain-bucket", REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_no_findings_when_no_buckets(self):
        findings = s3_checks.run(REGION)
        assert findings == []
