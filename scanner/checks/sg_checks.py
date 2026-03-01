"""
Security Group Checks
CIS AWS Benchmark: 5.2, 5.3, 5.4
"""
import boto3
from scanner.models import Finding, Severity, Status

# Ports that should never be open to the world
RESTRICTED_PORTS = {
    22:   ("SSH",        Severity.CRITICAL),
    3389: ("RDP",        Severity.CRITICAL),
    3306: ("MySQL",      Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    27017:("MongoDB",    Severity.HIGH),
    6379: ("Redis",      Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
}


def run(region: str) -> list[Finding]:
    client = boto3.client("ec2", region_name=region)
    findings = []

    paginator = client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            findings += _check_open_ports(sg, region)
            findings.append(_check_all_traffic_open(sg, region))
            findings.append(_check_default_sg_in_use(sg, region))

    return findings


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_open_to_world(rule: dict) -> bool:
    """True if a rule allows traffic from 0.0.0.0/0 OR ::/0."""
    ipv4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
    ipv6 = any(r.get("CidrIpv6") == "::/0"     for r in rule.get("Ipv6Ranges", []))
    return ipv4 or ipv6


def _covers_port(rule: dict, port: int) -> bool:
    """True if a rule's port range includes the given port."""
    if rule.get("IpProtocol") == "-1":   # all traffic — covers everything
        return True
    from_port = rule.get("FromPort", 0)
    to_port   = rule.get("ToPort",   0)
    return from_port <= port <= to_port


def _sg_label(sg: dict) -> str:
    """Human-readable label: 'sg-abc123 (my-sg-name)'."""
    name = sg.get("GroupName", "")
    return f"{sg['GroupId']} ({name})"


# ── individual checks ──────────────────────────────────────────────────────────

def _check_open_ports(sg: dict, region: str) -> list[Finding]:
    """SG-001 to SG-007: Known sensitive ports open to the world."""
    findings = []

    for rule in sg.get("IpPermissions", []):
        if not _is_open_to_world(rule):
            continue

        for port, (service_name, severity) in RESTRICTED_PORTS.items():
            if not _covers_port(rule, port):
                continue

            findings.append(Finding(
                check_id=f"SG-{port}",
                title=f"Security group allows unrestricted {service_name} access (port {port})",
                resource=_sg_label(sg),
                service="EC2/SecurityGroup",
                severity=severity,
                status=Status.FAIL,
                region=region,
                remediation=(
                    f"Remove inbound rule allowing 0.0.0.0/0 or ::/0 on port {port}. "
                    f"Restrict {service_name} access to specific trusted IP ranges only."
                ),
            ))

    # If no violations found for this SG, emit a PASS for the general open-port check
    if not findings:
        findings.append(Finding(
            check_id="SG-PORTS",
            title="Security group has no restricted ports open to the world",
            resource=_sg_label(sg),
            service="EC2/SecurityGroup",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            region=region,
            remediation="No action needed.",
        ))

    return findings


def _check_all_traffic_open(sg: dict, region: str) -> Finding:
    """SG-ALL: Security group must not allow all inbound traffic (protocol -1)."""
    all_open = any(
        rule.get("IpProtocol") == "-1" and _is_open_to_world(rule)
        for rule in sg.get("IpPermissions", [])
    )
    status = Status.FAIL if all_open else Status.PASS

    return Finding(
        check_id="SG-ALL",
        title="Security group allows ALL inbound traffic from the internet",
        resource=_sg_label(sg),
        service="EC2/SecurityGroup",
        severity=Severity.CRITICAL,
        status=status,
        region=region,
        remediation=(
            "Remove the inbound rule with protocol 'All' and source 0.0.0.0/0 or ::/0. "
            "Use explicit rules for only the ports and protocols your application needs."
        ),
    )


def _check_default_sg_in_use(sg: dict, region: str) -> Finding:
    """SG-DEFAULT: Default security group should not allow any traffic (CIS 5.4)."""
    if sg.get("GroupName") != "default":
        # Not a default SG — emit a PASS so we don't skip the check entirely
        return Finding(
            check_id="SG-DEFAULT",
            title="Non-default security group (default SG check skipped)",
            resource=_sg_label(sg),
            service="EC2/SecurityGroup",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            region=region,
            remediation="No action needed.",
        )

    has_inbound  = len(sg.get("IpPermissions", [])) > 0
    has_outbound = len(sg.get("IpPermissionsEgress", [])) > 0
    # Default SG always has one egress rule (allow all outbound) — only fail if inbound exists
    status = Status.FAIL if has_inbound else Status.PASS

    return Finding(
        check_id="SG-DEFAULT",
        title="Default security group allows inbound traffic",
        resource=_sg_label(sg),
        service="EC2/SecurityGroup",
        severity=Severity.MEDIUM,
        status=status,
        region=region,
        remediation=(
            "Remove all inbound rules from the default security group. "
            "Use custom security groups for all resources instead of the default."
        ),
    )
