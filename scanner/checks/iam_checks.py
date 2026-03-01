"""
IAM Security Checks
CIS AWS Benchmark: 1.x
"""
import boto3
from datetime import datetime, timezone
from scanner.models import Finding, Severity, Status

ACCESS_KEY_MAX_AGE_DAYS = 90


def run(region: str) -> list[Finding]:
    client = boto3.client("iam", region_name=region)
    findings = []

    findings.append(_check_root_mfa(client, region))
    findings.append(_check_root_access_keys(client, region))
    findings.append(_check_password_policy(client, region))
    findings += _check_access_key_age(client, region)

    return findings


# ── individual checks ──────────────────────────────────────────────────────────

def _check_root_mfa(client, region: str) -> Finding:
    """IAM-001: Root account must have MFA enabled (CIS 1.5)"""
    try:
        summary = client.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
        status = Status.PASS if mfa_enabled else Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="IAM-001",
        title="Root account does not have MFA enabled",
        resource="root",
        service="IAM",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            "Enable MFA on the root account immediately. "
            "Use a hardware MFA device or virtual MFA app (Google Authenticator, Authy)."
        ),
    )


def _check_root_access_keys(client, region: str) -> Finding:
    """IAM-002: Root account must not have active access keys (CIS 1.4)"""
    try:
        summary = client.get_account_summary()["SummaryMap"]
        has_keys = summary.get("AccountAccessKeysPresent", 0) > 0
        status = Status.FAIL if has_keys else Status.PASS
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="IAM-002",
        title="Root account has active access keys",
        resource="root",
        service="IAM",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            "Delete all access keys associated with the root account. "
            "Use IAM roles with least-privilege for programmatic access instead."
        ),
    )


def _check_password_policy(client, region: str) -> Finding:
    """IAM-003: Account password policy must meet minimum requirements (CIS 1.8-1.11)"""
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
        strong = (
            policy.get("MinimumPasswordLength", 0) >= 14
            and policy.get("RequireUppercaseCharacters", False)
            and policy.get("RequireLowercaseCharacters", False)
            and policy.get("RequireNumbers", False)
            and policy.get("RequireSymbols", False)
        )
        status = Status.PASS if strong else Status.FAIL
    except client.exceptions.NoSuchEntityException:
        status = Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="IAM-003",
        title="IAM password policy does not meet CIS minimum requirements",
        resource="account-password-policy",
        service="IAM",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation=(
            "Set password policy: min length 14, require uppercase, lowercase, "
            "numbers, and symbols."
        ),
    )


def _check_access_key_age(client, region: str) -> list[Finding]:
    """IAM-004: IAM user access keys must be rotated within 90 days (CIS 1.14)"""
    findings = []
    paginator = client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys_resp = client.list_access_keys(UserName=username)

            for key in keys_resp["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue

                created = key["CreateDate"]
                age_days = (datetime.now(timezone.utc) - created).days
                status = Status.FAIL if age_days > ACCESS_KEY_MAX_AGE_DAYS else Status.PASS

                findings.append(Finding(
                    check_id="IAM-004",
                    title=f"Access key older than {ACCESS_KEY_MAX_AGE_DAYS} days",
                    resource=f"{username}/{key['AccessKeyId']}",
                    service="IAM",
                    severity=Severity.MEDIUM,
                    status=status,
                    region=region,
                    remediation=(
                        f"Rotate access key {key['AccessKeyId']} for user {username}. "
                        "Create a new key, update applications, then deactivate and delete the old key."
                    ),
                ))

    return findings
