"""
Security Group Auto-Remediation Actions
"""
import logging
import boto3

logger = logging.getLogger(__name__)

# Ranges that are considered "open to the world"
OPEN_CIDRS = ["0.0.0.0/0", "::/0"]


def revoke_open_inbound_rules(sg_id: str, port: int, region: str, dry_run: bool) -> dict:
    """
    SG-001/ALL: Remove all inbound rules on a security group that allow
    the given port (or all traffic) from 0.0.0.0/0 or ::/0.
    """
    client = boto3.client("ec2", region_name=region)

    # Fetch current rules so we revoke exactly what exists (avoids API errors)
    sg = client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    rules_to_revoke = _find_open_rules(sg["IpPermissions"], port)

    if not rules_to_revoke:
        return {
            "action":   "SKIPPED",
            "resource": sg_id,
            "fix":      f"No open rules found for port {port}",
        }

    action = "WOULD_FIX" if dry_run else "FIXED"

    if not dry_run:
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=rules_to_revoke,
        )
        logger.info(
            "SG inbound rules revoked | sg=%s port=%s rules_removed=%d",
            sg_id, port, len(rules_to_revoke),
        )
    else:
        logger.info(
            "[DRY RUN] Would revoke %d rule(s) | sg=%s port=%s",
            len(rules_to_revoke), sg_id, port,
        )

    return {
        "action":       action,
        "resource":     sg_id,
        "rules_removed": len(rules_to_revoke),
        "fix":          f"Revoked {len(rules_to_revoke)} inbound rule(s) open to the internet on port {port}",
    }


def revoke_all_traffic_rule(sg_id: str, region: str, dry_run: bool) -> dict:
    """
    SG-ALL: Remove inbound rules with protocol -1 (all traffic) open to the world.
    """
    client = boto3.client("ec2", region_name=region)
    sg = client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

    rules_to_revoke = [
        rule for rule in sg["IpPermissions"]
        if rule.get("IpProtocol") == "-1" and _has_open_cidr(rule)
    ]

    if not rules_to_revoke:
        return {
            "action":   "SKIPPED",
            "resource": sg_id,
            "fix":      "No all-traffic open rules found",
        }

    action = "WOULD_FIX" if dry_run else "FIXED"

    if not dry_run:
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=rules_to_revoke,
        )
        logger.info("SG all-traffic rule revoked | sg=%s", sg_id)
    else:
        logger.info("[DRY RUN] Would revoke all-traffic rule | sg=%s", sg_id)

    return {
        "action":   action,
        "resource": sg_id,
        "fix":      "Revoked inbound rule allowing ALL traffic from the internet",
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _has_open_cidr(rule: dict) -> bool:
    ipv4 = any(r.get("CidrIp") in OPEN_CIDRS   for r in rule.get("IpRanges",   []))
    ipv6 = any(r.get("CidrIpv6") in OPEN_CIDRS  for r in rule.get("Ipv6Ranges", []))
    return ipv4 or ipv6


def _covers_port(rule: dict, port: int) -> bool:
    if rule.get("IpProtocol") == "-1":
        return True
    return rule.get("FromPort", 0) <= port <= rule.get("ToPort", 0)


def _find_open_rules(ip_permissions: list, port: int) -> list:
    """Return only the rules that are open to the world AND cover the given port."""
    return [
        rule for rule in ip_permissions
        if _has_open_cidr(rule) and _covers_port(rule, port)
    ]
