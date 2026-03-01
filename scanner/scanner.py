"""
CSPM Scanner — Lambda entry point
Triggered by EventBridge on a schedule.

Environment variables:
  FINDINGS_BUCKET      S3 bucket name to store findings JSON
  SNS_TOPIC_ARN        ARN of SNS topic for critical alerts
  REMEDIATOR_FUNCTION  Name of the Remediator Lambda to invoke
  AWS_REGION           Injected automatically by Lambda runtime
"""
import json
import logging
import os
from datetime import datetime

import boto3

from scanner.checks import s3_checks, iam_checks, sg_checks, cloudtrail_checks
from scanner.models import Finding, Severity, Status

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

FINDINGS_BUCKET      = os.environ["FINDINGS_BUCKET"]
SNS_TOPIC_ARN        = os.environ["SNS_TOPIC_ARN"]
REMEDIATOR_FUNCTION  = os.environ.get("REMEDIATOR_FUNCTION", "")


def lambda_handler(event, context):
    region = os.environ.get("AWS_REGION", "us-east-1")
    logger.info("CSPM scan started | region=%s", region)

    # ── run all check modules ─────────────────────────────────────────────────
    all_findings: list[Finding] = []
    all_findings += s3_checks.run(region)
    all_findings += iam_checks.run(region)
    all_findings += sg_checks.run(region)
    all_findings += cloudtrail_checks.run(region)

    # ── compute compliance score ──────────────────────────────────────────────
    total  = len(all_findings)
    passed = sum(1 for f in all_findings if f.status == Status.PASS)
    score  = round((passed / total) * 100, 1) if total > 0 else 100.0

    logger.info("Scan complete | total=%d passed=%d score=%.1f%%", total, passed, score)

    # ── store findings in S3 ──────────────────────────────────────────────────
    _save_findings(all_findings, score, region)

    # ── push compliance score to CloudWatch ──────────────────────────────────
    _publish_score_metric(score, region)

    # ── alert on critical failures ────────────────────────────────────────────
    critical_fails = [
        f for f in all_findings
        if f.status == Status.FAIL and f.severity == Severity.CRITICAL
    ]
    if critical_fails:
        _send_alert(critical_fails, score)

    # ── invoke remediator asynchronously ─────────────────────────────────────
    if REMEDIATOR_FUNCTION:
        _invoke_remediator(all_findings, region)

    return {
        "statusCode": 200,
        "score": score,
        "total": total,
        "passed": passed,
        "failed": total - passed,
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _save_findings(findings: list[Finding], score: float, region: str):
    """Write findings as a timestamped JSON file to S3."""
    s3 = boto3.client("s3", region_name=region)
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
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
