"""
CloudTrail Security Checks
CIS AWS Benchmark: 3.1 – 3.7
"""
import boto3
from scanner.models import Finding, Severity, Status


def run(region: str) -> list[Finding]:
    client = boto3.client("cloudtrail", region_name=region)
    findings = []

    try:
        trails = client.describe_trails(includeShadowTrails=False)["trailList"]
    except Exception:
        trails = []

    # Account-level check: at least one trail must exist
    findings.append(_check_trail_exists(trails, region))

    for trail in trails:
        findings.append(_check_multi_region(trail, region))
        findings.append(_check_log_validation(trail, region))
        findings.append(_check_cloudwatch_logs(trail, region))
        findings.append(_check_s3_public_access(trail, region))
        findings += _check_trail_logging(client, trail, region)

    return findings


# ── helpers ───────────────────────────────────────────────────────────────────

def _trail_label(trail: dict) -> str:
    return trail.get("Name", trail.get("TrailARN", "unknown"))


# ── individual checks ──────────────────────────────────────────────────────────

def _check_trail_exists(trails: list, region: str) -> Finding:
    """CT-001: At least one CloudTrail trail must exist (CIS 3.1)."""
    status = Status.PASS if trails else Status.FAIL

    return Finding(
        check_id="CT-001",
        title="No CloudTrail trail exists in this region",
        resource="cloudtrail",
        service="CloudTrail",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            "Create a CloudTrail trail and enable it for all regions. "
            "Store logs in a dedicated S3 bucket with restricted access."
        ),
    )


def _check_multi_region(trail: dict, region: str) -> Finding:
    """CT-002: Trail must be multi-region (CIS 3.1)."""
    is_multi = trail.get("IsMultiRegionTrail", False)
    status = Status.PASS if is_multi else Status.FAIL

    return Finding(
        check_id="CT-002",
        title="CloudTrail trail is not multi-region",
        resource=_trail_label(trail),
        service="CloudTrail",
        severity=Severity.HIGH,
        status=status,
        region=region,
        remediation=(
            "Enable multi-region logging on the trail so all AWS API activity "
            "is captured regardless of region."
        ),
    )


def _check_log_validation(trail: dict, region: str) -> Finding:
    """CT-003: Log file validation must be enabled (CIS 3.2)."""
    enabled = trail.get("LogFileValidationEnabled", False)
    status = Status.PASS if enabled else Status.FAIL

    return Finding(
        check_id="CT-003",
        title="CloudTrail log file validation is not enabled",
        resource=_trail_label(trail),
        service="CloudTrail",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation=(
            "Enable log file validation on the trail. This creates a digest file "
            "so you can detect if logs were modified or deleted after delivery."
        ),
    )


def _check_cloudwatch_logs(trail: dict, region: str) -> Finding:
    """CT-004: Trail must send logs to CloudWatch Logs (CIS 3.4)."""
    has_cw = bool(trail.get("CloudWatchLogsLogGroupArn"))
    status = Status.PASS if has_cw else Status.FAIL

    return Finding(
        check_id="CT-004",
        title="CloudTrail trail is not integrated with CloudWatch Logs",
        resource=_trail_label(trail),
        service="CloudTrail",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation=(
            "Configure the trail to send logs to a CloudWatch Logs log group. "
            "This enables real-time monitoring and metric filter alarms."
        ),
    )


def _check_s3_public_access(trail: dict, region: str) -> Finding:
    """CT-005: S3 bucket storing trail logs must not be publicly accessible (CIS 3.3)."""
    bucket_name = trail.get("S3BucketName", "")
    if not bucket_name:
        return Finding(
            check_id="CT-005",
            title="CloudTrail trail has no S3 bucket configured",
            resource=_trail_label(trail),
            service="CloudTrail",
            severity=Severity.HIGH,
            status=Status.FAIL,
            region=region,
            remediation="Configure an S3 bucket for the trail to store log files.",
        )

    s3 = boto3.client("s3")
    try:
        resp   = s3.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls",        False),
            config.get("IgnorePublicAcls",        False),
            config.get("BlockPublicPolicy",       False),
            config.get("RestrictPublicBuckets",   False),
        ])
        status = Status.PASS if all_blocked else Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="CT-005",
        title="S3 bucket storing CloudTrail logs is publicly accessible",
        resource=bucket_name,
        service="CloudTrail",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            f"Enable Block Public Access on bucket '{bucket_name}' "
            "to prevent log tampering or exposure."
        ),
    )


def _check_trail_logging(client, trail: dict, region: str) -> list[Finding]:
    """CT-006: Trail must have logging currently active (not paused)."""
    try:
        status_resp = client.get_trail_status(Name=trail["TrailARN"])
        is_logging  = status_resp.get("IsLogging", False)
        status      = Status.PASS if is_logging else Status.FAIL
    except Exception:
        status = Status.FAIL

    return [Finding(
        check_id="CT-006",
        title="CloudTrail trail logging is currently stopped",
        resource=_trail_label(trail),
        service="CloudTrail",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            "Start logging on the trail using the AWS Console or: "
            "aws cloudtrail start-logging --name <trail-name>"
        ),
    )]
