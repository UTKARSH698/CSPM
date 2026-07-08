"""
CSPM Scanner — Lambda entry point
Triggered by EventBridge on a schedule.

Environment variables:
  FINDINGS_BUCKET      S3 bucket name to store findings JSON
  SNS_TOPIC_ARN        ARN of SNS topic for critical alerts
  REMEDIATOR_FUNCTION  Name of the Remediator Lambda to invoke
  SCAN_REGIONS         Optional comma-separated regions for regional checks;
                       defaults to all enabled regions (auto-discovered)
  AWS_REGION           Injected automatically by Lambda runtime
"""
import json
import logging
import os
from datetime import datetime, timezone

import boto3

from scanner.checks import s3_checks, iam_checks, sg_checks, cloudtrail_checks
from scanner.models import Finding, Severity, Status

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

FINDINGS_BUCKET      = os.environ["FINDINGS_BUCKET"]
SNS_TOPIC_ARN        = os.environ["SNS_TOPIC_ARN"]
REMEDIATOR_FUNCTION  = os.environ.get("REMEDIATOR_FUNCTION", "")


def lambda_handler(event, context):
    home_region = os.environ.get("AWS_REGION", "us-east-1")
    regions = _get_regions(home_region)
    logger.info("CSPM scan started | home_region=%s regions=%s", home_region, regions)

    # ── run all check modules ─────────────────────────────────────────────────
    all_findings: list[Finding] = []

    # Global services (S3, IAM) are account-wide — scan once from the home region.
    all_findings += s3_checks.run(home_region)
    all_findings += iam_checks.run(home_region)

    # Regional services (Security Groups, CloudTrail) live per-region — scan each,
    # so a single-region trail or an exposed SG in any region isn't missed.
    for region in regions:
        all_findings += sg_checks.run(region)
        all_findings += cloudtrail_checks.run(region)

    # ── compute compliance score ──────────────────────────────────────────────
    summary = compute_summary(all_findings)
    score = summary["score"]

    logger.info(
        "Scan complete | total=%(total)d passed=%(passed)d failed=%(failed)d "
        "errored=%(errored)d score=%(score).1f%%", summary,
    )

    # ── store findings in S3 ──────────────────────────────────────────────────
    _save_findings(all_findings, score, home_region)

    # ── push compliance score to CloudWatch ──────────────────────────────────
    _publish_score_metric(score, home_region)

    # ── alert on critical failures ────────────────────────────────────────────
    critical_fails = [
        f for f in all_findings
        if f.status == Status.FAIL and f.severity == Severity.CRITICAL
    ]
    if critical_fails:
        _send_alert(critical_fails, score)

    # ── invoke remediator asynchronously ─────────────────────────────────────
    if REMEDIATOR_FUNCTION:
        _invoke_remediator(all_findings, home_region)

    return {"statusCode": 200, **summary}


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_regions(home_region: str) -> list[str]:
    """Regions to scan for regional services.

    A SCAN_REGIONS env var (comma-separated) pins the list explicitly — useful to
    bound cost/runtime. Otherwise all enabled regions are discovered dynamically,
    falling back to the home region if discovery fails (e.g. AccessDenied).
    """
    override = os.environ.get("SCAN_REGIONS", "").strip()
    if override:
        return [r.strip() for r in override.split(",") if r.strip()]

    try:
        ec2 = boto3.client("ec2", region_name=home_region)
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
    except Exception:
        logger.warning("Could not enumerate regions; falling back to %s", home_region)
        return [home_region]


def compute_summary(findings: list[Finding]) -> dict:
    """Tally findings into a compliance summary.

    Checks that couldn't be evaluated (ERROR) are indeterminate — excluded from
    the score denominator so a permissions gap doesn't silently tank compliance.
    """
    passed  = sum(1 for f in findings if f.status == Status.PASS)
    failed  = sum(1 for f in findings if f.status == Status.FAIL)
    errored = sum(1 for f in findings if f.status == Status.ERROR)
    scored  = passed + failed
    score   = round((passed / scored) * 100, 1) if scored > 0 else 100.0

    return {
        "score":   score,
        "total":   len(findings),
        "passed":  passed,
        "failed":  failed,
        "errored": errored,
    }

def _save_findings(findings: list[Finding], score: float, region: str):
    """Write findings as a timestamped JSON file to S3."""
    s3 = boto3.client("s3", region_name=region)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    key = f"findings/{timestamp}.json"

    payload = {
        "timestamp":  timestamp,
        "score":      score,
        "findings":   [f.to_dict() for f in findings],
    }

    s3.put_object(
        Bucket=FINDINGS_BUCKET,
        Key=key,
        Body=json.dumps(payload, indent=2),
        ContentType="application/json",
    )
    logger.info("Findings saved | bucket=%s key=%s", FINDINGS_BUCKET, key)


def _publish_score_metric(score: float, region: str):
    """Push compliance score to CloudWatch as a custom metric."""
    cw = boto3.client("cloudwatch", region_name=region)
    cw.put_metric_data(
        Namespace="CSPM",
        MetricData=[{
            "MetricName": "ComplianceScore",
            "Value":      score,
            "Unit":       "Percent",
        }],
    )
    logger.info("Metric published | ComplianceScore=%.1f", score)


def _send_alert(critical_fails: list[Finding], score: float):
    """Publish a summary of critical failures to SNS."""
    sns = boto3.client("sns")
    lines = [
        f"CSPM Alert — Compliance Score: {score}%",
        f"{len(critical_fails)} CRITICAL finding(s) detected:\n",
    ]
    for f in critical_fails:
        lines.append(f"  [{f.check_id}] {f.title}")
        lines.append(f"  Resource : {f.resource}")
        lines.append(f"  Fix      : {f.remediation}\n")

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[CSPM] {len(critical_fails)} Critical Finding(s) Detected",
        Message="\n".join(lines),
    )
    logger.info("SNS alert sent | critical_count=%d", len(critical_fails))


def _invoke_remediator(findings: list[Finding], region: str):
    """Asynchronously invoke the Remediator Lambda with the current findings."""
    lmb = boto3.client("lambda", region_name=region)
    payload = {
        "region":   region,
        "findings": [f.to_dict() for f in findings],
    }
    lmb.invoke(
        FunctionName=REMEDIATOR_FUNCTION,
        InvocationType="Event",          # async — scanner doesn't wait
        Payload=json.dumps(payload),
    )
    logger.info("Remediator invoked asynchronously | function=%s", REMEDIATOR_FUNCTION)
