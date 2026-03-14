"""
S3 Security Checks
CIS AWS Benchmark: 2.1.x
"""
import boto3
from scanner.models import Finding, Severity, Status


def run(region: str) -> list[Finding]:
    client = boto3.client("s3", region_name=region)
    findings = []

    response = client.list_buckets()
    buckets = [b["Name"] for b in response.get("Buckets", [])]

    for bucket in buckets:
        findings += [
            _check_public_access(client, bucket, region),
            _check_versioning(client, bucket, region),
            _check_logging(client, bucket, region),
            _check_encryption(client, bucket, region),
        ]

    return findings


# ── individual checks ──────────────────────────────────────────────────────────

def _check_public_access(client, bucket: str, region: str) -> Finding:
    """S3-001: Bucket must have Block Public Access enabled (CIS 2.1.5)"""
    try:
        resp = client.get_public_access_block(Bucket=bucket)
        config = resp["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])
        status = Status.PASS if all_blocked else Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="S3-001",
        title="S3 bucket Block Public Access is not fully enabled",
        resource=bucket,
        service="S3",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            "Enable all four Block Public Access settings on the bucket: "
            "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
        ),
    )


def _check_versioning(client, bucket: str, region: str) -> Finding:
    """S3-002: Versioning should be enabled (CIS 2.1.3)"""
    try:
        resp = client.get_bucket_versioning(Bucket=bucket)
        enabled = resp.get("Status") == "Enabled"
        status = Status.PASS if enabled else Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="S3-002",
        title="S3 bucket versioning is not enabled",
        resource=bucket,
        service="S3",
        severity=Severity.LOW,
        status=status,
        region=region,
        remediation="Enable versioning on the bucket to protect against accidental deletion.",
    )


def _check_logging(client, bucket: str, region: str) -> Finding:
    """S3-003: Server access logging should be enabled (CIS 2.1.1)"""
    try:
        resp = client.get_bucket_logging(Bucket=bucket)
        enabled = "LoggingEnabled" in resp
        status = Status.PASS if enabled else Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="S3-003",
        title="S3 bucket access logging is not enabled",
        resource=bucket,
        service="S3",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation="Enable server access logging on the bucket and point logs to a dedicated logging bucket.",
    )


def _check_encryption(client, bucket: str, region: str) -> Finding:
    """S3-004: Default encryption should be enabled (CIS 2.1.1)"""
    try:
        client.get_bucket_encryption(Bucket=bucket)
        status = Status.PASS
    except client.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            status = Status.FAIL
        else:
            status = Status.FAIL
    except Exception:
        status = Status.FAIL

    return Finding(
        check_id="S3-004",
        title="S3 bucket default encryption is not enabled",
        resource=bucket,
        service="S3",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
    )
