"""
Unit tests for scanner/checks/iam_checks.py
Uses moto to mock IAM API calls.
"""
import boto3
import pytest
from datetime import datetime, timezone, timedelta
from moto import mock_aws
from unittest.mock import patch, MagicMock
from scanner.checks import iam_checks
from scanner.models import Status, Severity


REGION = "us-east-1"


# ── IAM-001: Root MFA ─────────────────────────────────────────────────────────

class TestCheckRootMfa:
    @mock_aws
    def test_pass_when_root_mfa_enabled(self):
        iam = boto3.client("iam", region_name=REGION)
        # moto get_account_summary returns AccountMFAEnabled=1 by default
        # We patch to explicitly test both cases
        with patch.object(iam, "get_account_summary", return_value={
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }):
            finding = iam_checks._check_root_mfa(iam, REGION)
        assert finding.status == Status.PASS
        assert finding.check_id == "IAM-001"

    @mock_aws
    def test_fail_when_root_mfa_disabled(self):
        iam = boto3.client("iam", region_name=REGION)
        with patch.object(iam, "get_account_summary", return_value={
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
        }):
            finding = iam_checks._check_root_mfa(iam, REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_fail_on_exception(self):
        iam = boto3.client("iam", region_name=REGION)
        with patch.object(iam, "get_account_summary", side_effect=Exception("Access denied")):
            finding = iam_checks._check_root_mfa(iam, REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_critical_severity(self):
        iam = boto3.client("iam", region_name=REGION)
        with patch.object(iam, "get_account_summary", return_value={
            "SummaryMap": {"AccountMFAEnabled": 0}
        }):
            finding = iam_checks._check_root_mfa(iam, REGION)
        assert finding.severity == Severity.CRITICAL


# ── IAM-002: Root Access Keys ─────────────────────────────────────────────────

class TestCheckRootAccessKeys:
    @mock_aws
    def test_pass_when_no_root_keys(self):
        iam = boto3.client("iam", region_name=REGION)
        with patch.object(iam, "get_account_summary", return_value={
            "SummaryMap": {"AccountAccessKeysPresent": 0}
        }):
            finding = iam_checks._check_root_access_keys(iam, REGION)
        assert finding.status == Status.PASS

    @mock_aws
    def test_fail_when_root_keys_present(self):
        iam = boto3.client("iam", region_name=REGION)
        with patch.object(iam, "get_account_summary", return_value={
            "SummaryMap": {"AccountAccessKeysPresent": 1}
        }):
            finding = iam_checks._check_root_access_keys(iam, REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_critical_severity(self):
        iam = boto3.client("iam", region_name=REGION)
        with patch.object(iam, "get_account_summary", return_value={
            "SummaryMap": {"AccountAccessKeysPresent": 1}
        }):
            finding = iam_checks._check_root_access_keys(iam, REGION)
        assert finding.severity == Severity.CRITICAL


# ── IAM-003: Password Policy ──────────────────────────────────────────────────

class TestCheckPasswordPolicy:
    @mock_aws
    def test_pass_with_strong_policy(self):
        iam = boto3.client("iam", region_name=REGION)
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True,
        )
        finding = iam_checks._check_password_policy(iam, REGION)
        assert finding.status == Status.PASS

    @mock_aws
    def test_fail_when_password_too_short(self):
        iam = boto3.client("iam", region_name=REGION)
        iam.update_account_password_policy(
            MinimumPasswordLength=8,   # ← too short (< 14)
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True,
        )
        finding = iam_checks._check_password_policy(iam, REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_fail_when_no_policy_set(self):
        iam = boto3.client("iam", region_name=REGION)
        # No policy configured
        finding = iam_checks._check_password_policy(iam, REGION)
        assert finding.status == Status.FAIL

    @mock_aws
    def test_fail_when_symbols_not_required(self):
        iam = boto3.client("iam", region_name=REGION)
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=False,   # ← missing
        )
        finding = iam_checks._check_password_policy(iam, REGION)
        assert finding.status == Status.FAIL


# ── IAM-004: Access Key Age ───────────────────────────────────────────────────

class TestCheckAccessKeyAge:
    @mock_aws
    def test_pass_for_fresh_key(self):
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="fresh-user")
        iam.create_access_key(UserName="fresh-user")
        findings = iam_checks._check_access_key_age(iam, REGION)
        assert all(f.status == Status.PASS for f in findings)

    @mock_aws
    def test_fail_for_old_key(self):
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="old-user")
        key = iam.create_access_key(UserName="old-user")["AccessKey"]

        old_date = datetime.now(timezone.utc) - timedelta(days=100)
        with patch("scanner.checks.iam_checks.datetime") as mock_dt:
            mock_dt.now.return_value = datetime.now(timezone.utc)
            # Patch the key's CreateDate
            with patch.object(
                iam, "list_access_keys",
                return_value={"AccessKeyMetadata": [{
                    "UserName": "old-user",
                    "AccessKeyId": key["AccessKeyId"],
                    "Status": "Active",
                    "CreateDate": old_date,
                }]}
            ):
                findings = iam_checks._check_access_key_age(iam, REGION)
        assert any(f.status == Status.FAIL for f in findings)

    @mock_aws
    def test_skip_inactive_keys(self):
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="inactive-user")
        key = iam.create_access_key(UserName="inactive-user")["AccessKey"]
        iam.update_access_key(
            UserName="inactive-user",
            AccessKeyId=key["AccessKeyId"],
            Status="Inactive",
        )
        findings = iam_checks._check_access_key_age(iam, REGION)
        # Inactive keys are skipped — no findings
        assert findings == []

    @mock_aws
    def test_no_findings_when_no_users(self):
        iam = boto3.client("iam", region_name=REGION)
        findings = iam_checks._check_access_key_age(iam, REGION)
        assert findings == []
