"""
S3 Auto-Remediation Actions
"""
import logging
import boto3

logger = logging.getLogger(__name__)


def block_public_access(bucket: str, region: str, dry_run: bool) -> dict:
    """
    CT-001 / S3-001: Enable all four Block Public Access settings on a bucket.
    Returns a result dict describing what was done (or would be done).
    """
    action = "WOULD_FIX" if dry_run else "FIXED"

    if not dry_run:
        client = boto3.client("s3", region_name=region)
        client.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.info("S3 Block Public Access enabled | bucket=%s", bucket)
    else:
        logger.info("[DRY RUN] Would enable Block Public Access | bucket=%s", bucket)

    return {
        "action":   action,
        "resource": bucket,
        "fix":      "Enabled all four S3 Block Public Access settings",
    }


def enable_versioning(bucket: str, region: str, dry_run: bool) -> dict:
    """S3-002: Enable versioning on a bucket."""
    action = "WOULD_FIX" if dry_run else "FIXED"

    if not dry_run:
        client = boto3.client("s3", region_name=region)
        client.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        logger.info("S3 versioning enabled | bucket=%s", bucket)
    else:
        logger.info("[DRY RUN] Would enable versioning | bucket=%s", bucket)

    return {
        "action":   action,
        "resource": bucket,
        "fix":      "Enabled S3 bucket versioning",
    }
