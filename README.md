<div align="center">

# 🔐 CSPM — Cloud Security Posture Management

### Automated AWS security scanning, alerting, and auto-remediation — serverless, event-driven, zero cost.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white)
![AWS Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![CIS Benchmark](https://img.shields.io/badge/CIS_AWS_Benchmark-v1.5-green?style=for-the-badge)

</div>

---

## The Problem

Cloud misconfigurations are the **#1 cause of cloud data breaches** — not complex attacks, just simple mistakes.

An S3 bucket accidentally left public. SSH open to the entire internet. A root account with no MFA. These are the findings that make headlines. CSPM catches them automatically, alerts you immediately, and fixes the safe ones without human intervention.

---

## Live Demo

> First scan on a brand new AWS account — detected and alerted within seconds.

```
CSPM scan started | region=us-east-1

Scan complete | total=25  passed=20  score=80.0%

[CRITICAL] IAM-001 - Root account does not have MFA enabled
[CRITICAL] CT-001  - No CloudTrail trail exists in this region
[CRITICAL] SG-22   - Security group allows unrestricted SSH access (port 22)

SNS alert sent | critical_count=3
Remediator invoked asynchronously
Findings saved → s3://cspm-findings-<your-account-id>/findings/2026-03-08T09-18-09Z.json
Metric published → CloudWatch: ComplianceScore = 80.0
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           AWS Cloud                                  │
│                                                                      │
│   ┌─────────────────┐                                                │
│   │  EventBridge    │  runs every hour                               │
│   └────────┬────────┘                                                │
│            │                                                         │
│            ▼                                                         │
│   ┌─────────────────┐   scans    ┌─────────────────────────────┐    │
│   │  Scanner Lambda │──────────▶ │  S3 · IAM · EC2 · CloudTrail│    │
│   └────────┬────────┘            └─────────────────────────────┘    │
│            │                                                         │
│     ┌──────┼────────────┬────────────────────┐                      │
│     ▼      ▼            ▼                    ▼                      │
│  ┌──────┐ ┌──────────┐ ┌───────────┐  ┌───────────────┐            │
│  │  S3  │ │CloudWatch│ │    SNS    │  │  Remediator   │            │
│  │      │ │          │ │           │  │    Lambda     │            │
│  │findings│ │  score  │ │ email alert│  │               │            │
│  └──────┘ └──────────┘ └───────────┘  └──────┬────────┘            │
│                                               │                      │
│                                    auto-fix S3 public access         │
│                                    auto-revoke open SG rules         │
│                                    save audit report to S3           │
└──────────────────────────────────────────────────────────────────────┘
```

**Flow:** EventBridge triggers Scanner hourly → Scanner audits 4 AWS services → Findings saved to S3 → Score published to CloudWatch → Critical findings trigger SNS email → Scanner asynchronously invokes Remediator → Remediator auto-fixes safe issues and logs the rest.

---

## What It Checks

### 19+ Security Checks mapped to CIS AWS Foundations Benchmark v1.5

| Service | Check ID | Finding | Severity | CIS Ref |
|---|---|---|---|---|
| S3 | S3-001 | Block Public Access not fully enabled | 🔴 Critical | 2.1.5 |
| S3 | S3-002 | Versioning disabled | 🟡 Low | 2.1.3 |
| S3 | S3-003 | Access logging disabled | 🟠 Medium | 2.1.1 |
| S3 | S3-004 | Default encryption disabled | 🟠 Medium | 2.1.1 |
| IAM | IAM-001 | Root account MFA disabled | 🔴 Critical | 1.5 |
| IAM | IAM-002 | Root account has active access keys | 🔴 Critical | 1.4 |
| IAM | IAM-003 | Password policy below CIS minimum | 🟠 Medium | 1.8–1.11 |
| IAM | IAM-004 | Access key older than 90 days | 🟠 Medium | 1.14 |
| EC2/SG | SG-22 | SSH open to 0.0.0.0/0 | 🔴 Critical | 5.2 |
| EC2/SG | SG-3389 | RDP open to 0.0.0.0/0 | 🔴 Critical | 5.3 |
| EC2/SG | SG-3306/5432/27017/6379/9200 | Database ports exposed to internet | 🟥 High | 5.x |
| EC2/SG | SG-ALL | All traffic allowed (protocol -1) | 🔴 Critical | 5.x |
| EC2/SG | SG-DEFAULT | Default security group has inbound rules | 🟠 Medium | 5.4 |
| CloudTrail | CT-001 | No trail exists | 🔴 Critical | 3.1 |
| CloudTrail | CT-002 | Trail is not multi-region | 🟥 High | 3.1 |
| CloudTrail | CT-003 | Log file validation disabled | 🟠 Medium | 3.2 |
| CloudTrail | CT-004 | Not integrated with CloudWatch Logs | 🟠 Medium | 3.4 |
| CloudTrail | CT-005 | Log bucket is publicly accessible | 🔴 Critical | 3.3 |
| CloudTrail | CT-006 | Logging currently paused | 🔴 Critical | 3.1 |

---

## Auto-Remediation

The Remediator Lambda auto-fixes findings that are safe to correct programmatically. Everything else is flagged for human review.

| Finding | Auto-Fix Applied |
|---|---|
| S3 public access enabled | Enables all 4 Block Public Access settings |
| S3 versioning disabled | Enables versioning on the bucket |
| SSH / RDP open to internet | Revokes the specific offending inbound rule |
| All-traffic SG rule | Removes the open-world inbound rule |
| IAM / CloudTrail issues | ⚠️ Logged for human review — too risky to auto-fix |

> **DRY_RUN mode** — deploys with `DRY_RUN=true` by default. Logs every fix it *would* make without touching anything. Flip to `false` once you've reviewed the findings.

Every remediation action is written as a timestamped JSON audit report to S3.

---

## Compliance Score & Dashboard

After each scan, a score is computed and pushed to CloudWatch as a custom metric:

```
Score = (Passed Checks / Total Checks) × 100
```

A live **CloudWatch Dashboard** is deployed automatically — showing compliance score, 7-day trend, Lambda invocations, and error rates in one view.

![Compliance Score](demo/dashboard-score.png)

![Full Dashboard](demo/dashboard-full.png)

Score progression on this account (brand new → secured):

```
Scan 1 — new account, no config:   66.7%   ██████████████████░░░░░░░░░░░
Scan 2 — CloudTrail created:       68.0%   ██████████████████░░░░░░░░░░░
Scan 3 — IAM + SG + CT fixed:     76.0%   ██████████████████████░░░░░░░
Scan 4 — CW Logs linked:          80.0%   ████████████████████████░░░░░
```

---

## Tech Stack & AWS Services

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Compute | AWS Lambda (Scanner + Remediator) |
| Scheduling | AWS EventBridge (hourly cron trigger) |
| Storage | AWS S3 (findings JSON + audit reports) |
| Alerting | AWS SNS (email on critical findings) |
| Monitoring | AWS CloudWatch (custom metrics + dashboard) |
| Security APIs | AWS IAM · EC2 · CloudTrail |
| IaC | Terraform |
| CI/CD | GitHub Actions |
| AWS SDK | boto3 |
| Testing | pytest |
| Linting | ruff |

---

## Project Structure

```
cspm/
├── scanner/
│   ├── models.py                  # Finding dataclass (check_id, severity, status, remediation)
│   ├── scanner.py                 # Lambda handler — orchestrates all checks
│   └── checks/
│       ├── s3_checks.py           # 4 checks: public access, versioning, logging, encryption
│       ├── iam_checks.py          # 4 checks: root MFA, root keys, password policy, key age
│       ├── sg_checks.py           # 9+ checks: SSH, RDP, DB ports, all-traffic, default SG
│       └── cloudtrail_checks.py   # 6 checks: trail exists, multi-region, validation, CW Logs
├── remediator/
│   ├── remediator.py              # Lambda handler + check_id dispatcher
│   └── actions/
│       ├── s3_actions.py          # block_public_access(), enable_versioning()
│       └── sg_actions.py          # revoke_open_inbound_rules(), revoke_all_traffic_rule()
├── infrastructure/
│   ├── main.tf                    # Provider + AWS account data source
│   ├── variables.tf               # aws_region, alert_email, dry_run, scan_schedule
│   ├── s3.tf                      # Findings bucket (encrypted, versioned, 90-day lifecycle)
│   ├── sns.tf                     # Alert topic + email subscription
│   ├── iam.tf                     # Least-privilege roles for scanner + remediator
│   ├── lambda.tf                  # Both Lambda functions + shared zip packaging
│   ├── eventbridge.tf             # Hourly schedule + Lambda invoke permission
│   ├── cloudwatch_dashboard.tf    # Live dashboard: score trend, invocations, errors
│   ├── outputs.tf                 # Bucket name, function names, manual invoke command
│   └── terraform.tfvars.example   # Safe template — copy to terraform.tfvars
├── tests/
│   └── test_models.py             # Unit tests for the Finding model
├── .github/workflows/
│   └── pipeline.yml               # CI: lint + test on PR | CD: terraform deploy on main
└── requirements.txt
```

---

## Deploy

### Prerequisites
- AWS account (Free Tier is sufficient)
- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.5
- Python 3.11+
- AWS CLI configured (`aws configure`)

### One-time setup

```bash
# 1. Clone
git clone https://github.com/UTKARSH698/CSPM.git
cd CSPM/infrastructure

# 2. Set your variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — fill in alert_email and aws_region

# 3. Deploy (19 AWS resources created automatically)
terraform init
terraform apply

# 4. Confirm the SNS subscription email AWS sends you

# 5. Run your first manual scan
aws lambda invoke --function-name cspm-scanner --region us-east-1 result.json
cat result.json

# 6. View the live dashboard
# AWS Console → CloudWatch → Dashboards → CSPM-Security-Posture
```

### CI/CD via GitHub Actions

Every push to `main` automatically lints, tests, and deploys.

Add these 4 secrets to your repo under `Settings → Secrets → Actions`:

| Secret | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `AWS_REGION` | `us-east-1` |
| `ALERT_EMAIL` | Email for security alerts |

---

## Design Decisions

**DRY_RUN by default**
The remediator deploys safe. It logs every fix it would make without applying anything. Switch to `false` only after reviewing your first few findings.

**Async remediation**
Scanner invokes the remediator with `InvocationType=Event` (fire-and-forget). Scanner latency stays under 6 seconds regardless of how many issues need fixing.

**IAM and CloudTrail not auto-fixed**
Automatically rotating access keys or modifying trail configurations risks breaking production workloads. These are flagged for human review with clear remediation instructions.

**IPv4 + IPv6 both checked**
Security group checks cover `0.0.0.0/0` (IPv4) and `::/0` (IPv6). Most similar tools miss IPv6 entirely.

**Port range awareness**
A rule allowing TCP `0–65535` still triggers the SSH check. Most tools only match exact port numbers — this one checks if the port falls within the rule's range.

**Least-privilege IAM**
Scanner role: read-only on S3, IAM, EC2, CloudTrail. Remediator role: only the specific write actions it needs. Neither role has admin access.

**Single zip, two Lambdas**
Both Lambda functions share one deployment package. Different handler paths point to the correct entry point. Simpler packaging, smaller attack surface.

---

## AWS Free Tier Usage

| Service | How Used | Free Limit |
|---|---|---|
| Lambda | 2 invocations/hour (scanner + remediator) | 1M req/month |
| EventBridge | 1 scheduled event/hour | 1M events/month |
| S3 | ~10 KB JSON per scan | 5 GB |
| CloudWatch | 1 custom metric per scan | 10 metrics free |
| SNS | Email on critical findings only | 1M publishes/month |

**Estimated monthly cost: $0**

---

## Author

**Utkarsh Batham** — B.Tech CSE · Cloud Technology & Information Security

[![GitHub](https://img.shields.io/badge/GitHub-UTKARSH698-181717?style=flat&logo=github)](https://github.com/UTKARSH698)
