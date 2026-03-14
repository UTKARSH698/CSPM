"""
Unit tests for scanner/checks/sg_checks.py
Uses moto to mock EC2/Security Group API calls.
"""
import boto3
import pytest
from moto import mock_aws
from scanner.checks import sg_checks
from scanner.models import Status, Severity


REGION = "us-east-1"


def _create_sg(ec2, name: str, description: str = "test sg") -> dict:
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    sg = ec2.create_security_group(
        GroupName=name,
        Description=description,
        VpcId=vpc["Vpc"]["VpcId"],
    )
    return sg["GroupId"]


# ── helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_is_open_to_world_ipv4(self):
        rule = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
        assert sg_checks._is_open_to_world(rule) is True

    def test_is_open_to_world_ipv6(self):
        rule = {"IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
        assert sg_checks._is_open_to_world(rule) is True

    def test_is_not_open_to_world(self):
        rule = {"IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": []}
        assert sg_checks._is_open_to_world(rule) is False

    def test_covers_port_exact(self):
        rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}
        assert sg_checks._covers_port(rule, 22) is True

    def test_covers_port_range(self):
        rule = {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}
        assert sg_checks._covers_port(rule, 3306) is True

    def test_covers_port_all_traffic(self):
        rule = {"IpProtocol": "-1"}
        assert sg_checks._covers_port(rule, 22) is True

    def test_does_not_cover_port(self):
        rule = {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80}
        assert sg_checks._covers_port(rule, 22) is False


# ── SG-001 to SG-007: Restricted ports ───────────────────────────────────────

class TestCheckOpenPorts:
    @mock_aws
    def test_fail_ssh_open_to_world(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg_id = _create_sg(ec2, "ssh-open")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        findings = sg_checks._check_open_ports(sg, REGION)
        assert any(f.check_id == "SG-22" and f.status == Status.FAIL for f in findings)

    @mock_aws
    def test_fail_rdp_open_to_world(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg_id = _create_sg(ec2, "rdp-open")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        findings = sg_checks._check_open_ports(sg, REGION)
        assert any(f.check_id == "SG-3389" and f.status == Status.FAIL for f in findings)

    @mock_aws
    def test_pass_when_ssh_restricted_to_cidr(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg_id = _create_sg(ec2, "ssh-restricted")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "192.168.1.0/24"}],   # restricted
            }],
        )
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        findings = sg_checks._check_open_ports(sg, REGION)
        # Should emit PASS (no restricted ports open to world)
        assert all(f.status == Status.PASS for f in findings)

    @mock_aws
    def test_pass_when_no_inbound_rules(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg_id = _create_sg(ec2, "clean-sg")
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        findings = sg_checks._check_open_ports(sg, REGION)
        assert all(f.status == Status.PASS for f in findings)


# ── SG-ALL: All traffic open ──────────────────────────────────────────────────

class TestCheckAllTrafficOpen:
    @mock_aws
    def test_fail_when_all_traffic_open(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg_id = _create_sg(ec2, "all-open")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        finding = sg_checks._check_all_traffic_open(sg, REGION)
        assert finding.status == Status.FAIL
        assert finding.severity == Severity.CRITICAL

    @mock_aws
    def test_pass_when_specific_port_only(self):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg_id = _create_sg(ec2, "port-only")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        finding = sg_checks._check_all_traffic_open(sg, REGION)
        assert finding.status == Status.PASS


# ── SG-DEFAULT: Default SG ────────────────────────────────────────────────────

class TestCheckDefaultSg:
    def test_pass_for_non_default_sg(self):
        sg = {
            "GroupId": "sg-abc123",
            "GroupName": "my-custom-sg",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        }
        finding = sg_checks._check_default_sg_in_use(sg, REGION)
        assert finding.status == Status.PASS

    def test_fail_when_default_sg_has_inbound_rules(self):
        sg = {
            "GroupId": "sg-default",
            "GroupName": "default",
            "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            "IpPermissionsEgress": [],
        }
        finding = sg_checks._check_default_sg_in_use(sg, REGION)
        assert finding.status == Status.FAIL

    def test_pass_when_default_sg_has_no_inbound(self):
        sg = {
            "GroupId": "sg-default",
            "GroupName": "default",
            "IpPermissions": [],
            "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }
        finding = sg_checks._check_default_sg_in_use(sg, REGION)
        assert finding.status == Status.PASS
