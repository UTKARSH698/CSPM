"""
IAM Security Checks
CIS AWS Benchmark: 1.x
"""
import boto3
from datetime import datetime, timezone
from scanner.aws_errors import status_from_error
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
    except Exception as e:
        status = status_from_error(e)

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
    except Exception as e:
        status = status_from_error(e)

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
    except Exception as e:
        # NoSuchEntity means no password policy is set at all → non-compliant.
        status = status_from_error(e, {"NoSuchEntity"})

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

    try:
        pages = list(client.get_paginator("list_users").paginate())
    except Exception as e:
        return [_key_age_finding(
            resource="iam-access-keys",
            status=status_from_error(e),
            region=region,
            title="Could not list IAM users to audit access key age",
            remediation="Grant the scanner iam:ListUsers/iam:ListAccessKeys and re-run.",
        )]

    for page in pages:
        for user in page["Users"]:
            username = user["UserName"]
            try:
                keys = client.list_access_keys(UserName=username)["AccessKeyMetadata"]
            except Exception as e:
                findings.append(_key_age_finding(
                    resource=username,
                    status=status_from_error(e),
                    region=region,
                    title=f"Could not list access keys for user {username}",
                    remediation="Grant the scanner iam:ListAccessKeys and re-run.",
                ))
                continue

            for key in keys:
                if key["Status"] != "Active":
                    continue

                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                status = Status.FAIL if age_days > ACCESS_KEY_MAX_AGE_DAYS else Status.PASS
                verb = "older than" if status == Status.FAIL else "rotated within"

                findings.append(_key_age_finding(
                    resource=f"{username}/{key['AccessKeyId']}",
                    status=status,
                    region=region,
                    title=f"Access key {verb} {ACCESS_KEY_MAX_AGE_DAYS} days",
                    remediation=(
                        f"Rotate access key {key['AccessKeyId']} for user {username}. "
                        "Create a new key, update applications, then deactivate and delete the old key."
                    ),
                ))

    return findings


def _key_age_finding(resource: str, status: Status, region: str,
                     title: str, remediation: str) -> Finding:
    return Finding(
        check_id="IAM-004",
        title=title,
        resource=resource,
        service="IAM",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation=remediation,
    )
