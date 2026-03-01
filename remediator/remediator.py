"""
CSPM Remediator — Lambda entry point
Invoked by the Scanner Lambda after each scan.

Receives a list of CRITICAL/HIGH FAIL findings and auto-fixes
what it knows how to fix. Everything else is skipped and logged.

Environment variables:
  DRY_RUN           "true" to log fixes without applying them (default: "false")
  FINDINGS_BUCKET   S3 bucket to write the remediation report
  AWS_REGION        Injected automatically by Lambda runtime
"""
import json
import logging
import os
from datetime import datetime

import boto3

from remediator.actions import s3_actions, sg_actions

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

DRY_RUN         = os.environ.get("DRY_RUN", "false").lower() == "true"
FINDINGS_BUCKET = os.environ["FINDINGS_BUCKET"]

def lambda_handler(event, context):
    """
    Expected event shape (sent by scanner.py):
    {
        "findings": [ { "check_id": ..., "resource": ..., "status": "FAIL", ... } ],
        "region":   "us-east-1"
    }
    """
    region   = event.get("region", os.environ.get("AWS_REGION", "us-east-1"))
    findings = event.get("findings", [])

    if DRY_RUN:
        logger.info("Remediator running in DRY RUN mode — no changes will be made")

    # Only attempt to fix FAIL findings
    failed = [f for f in findings if f.get("status") == "FAIL"]
    logger.info("Remediator started | total_findings=%d failed=%d dry_run=%s",
                len(findings), len(failed), DRY_RUN)

    results = []
    for finding in failed:
        result = _dispatch(finding, region)
        if result:
            results.append(result)

    _save_report(results, region)

    logger.info("Remediation complete | actions_taken=%d", len(results))
    return {
        "statusCode":     200,
        "dry_run":        DRY_RUN,
        "actions_taken":  len(results),
        "results":        results,
    }


# ── dispatcher ────────────────────────────────────────────────────────────────

def _dispatch(finding: dict, region: str) -> dict | None:
    check_id = finding.get("check_id", "")
    resource = finding.get("resource", "")

    # S3 checks
    if check_id == "S3-001":
        return s3_actions.block_public_access(resource, region, DRY_RUN)

    if check_id == "S3-002":
        return s3_actions.enable_versioning(resource, region, DRY_RUN)

    # SG — all-traffic rule
    if check_id == "SG-ALL":
        sg_id = _parse_sg_id(resource)
        return sg_actions.revoke_all_traffic_rule(sg_id, region, DRY_RUN)

    # SG — specific port (check_id format: "SG-<port>", e.g. "SG-22")
    if check_id.startswith("SG-") and check_id[3:].isdigit():
        port  = int(check_id[3:])
        sg_id = _parse_sg_id(resource)
        return sg_actions.revoke_open_inbound_rules(sg_id, port, region, DRY_RUN)

    # Everything else (IAM, CloudTrail) requires human action — skip
    logger.info("No auto-remediation available | check_id=%s resource=%s", check_id, resource)
    return None


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_sg_id(resource: str) -> str:
    """Extract sg-xxxxxxxx from a label like 'sg-abc123 (my-sg-name)'."""
    return resource.split(" ")[0]


def _save_report(results: list, region: str):
    """Write the remediation report as a timestamped JSON file to S3."""
    s3        = boto3.client("s3", region_name=region)
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    key       = f"remediation-reports/{timestamp}.json"

    payload = {
        "timestamp": timestamp,
        "dry_run":   DRY_RUN,
        "results":   results,
    }

    s3.put_object(
        Bucket=FINDINGS_BUCKET,
        Key=key,
        Body=json.dumps(payload, indent=2),
        ContentType="application/json",
    )
    logger.info("Remediation report saved | bucket=%s key=%s", FINDINGS_BUCKET, key)
