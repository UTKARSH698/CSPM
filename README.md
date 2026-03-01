# CSPM — Cloud Security Posture Management

An automated, serverless security scanner for AWS that continuously audits cloud infrastructure against the **CIS AWS Foundations Benchmark v1.5**, alerts on misconfigurations, and auto-remediates critical findings — all within the AWS Free Tier.

---

## The Problem

Cloud misconfigurations are the #1 cause of cloud data breaches. An S3 bucket left public, an SSH port open to the world, a root account without MFA — these are not complex attacks. They are simple mistakes that automated tooling should catch and fix.

CSPM does exactly that.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Cloud                                │
│                                                             │
│   EventBridge (hourly)                                      │
│         │                                                   │
│         ▼                                                   │
│   ┌─────────────┐    reads     ┌──────────────────────┐    │
│   │   Scanner   │─────────────▶│  S3 / IAM / EC2 /    │    │
│   │   Lambda    │              │  CloudTrail APIs      │    │
│   └──────┬──────┘              └──────────────────────┘    │
│          │                                                   │
│    ┌─────┼──────────┬─────────────────┐                     │
│    ▼     ▼          ▼                 ▼                     │
│  ┌───┐ ┌────┐  ┌─────────┐   ┌────────────┐               │
│  │ S3│ │ CW │  │   SNS   │   │ Remediator │               │
│  │   │ │    │  │ (email) │   │   Lambda   │               │
│  │findings│ │score│  │ alerts  │   │            │               │
│  └───┘ └────┘  └─────────┘   └─────┬──────┘               │
│                                     │                       │
│                              auto-fix S3 + SGs              │
│                              saves audit report to S3        │
└─────────────────────────────────────────────────────────────┘
```

**Flow**: EventBridge triggers the Scanner Lambda hourly → Scanner audits S3, IAM, Security Groups, and CloudTrail → Findings stored in S3 → Compliance score pushed to CloudWatch → Critical findings trigger SNS email alert → Scanner asynchronously invokes the Remediator Lambda → Remediator auto-fixes what it can, logs everything else.

---

## Features

### 19+ Security Checks (CIS AWS Foundations Benchmark v1.5)

| Service | Check | Severity | CIS Reference |
|---|---|---|---|
| S3 | Block Public Access not fully enabled | Critical | 2.1.5 |
| S3 | Versioning disabled | Low | 2.1.3 |
| S3 | Access logging disabled | Medium | 2.1.1 |
| S3 | Default encryption disabled | Medium | 2.1.1 |
| IAM | Root account MFA disabled | Critical | 1.5 |
| IAM | Root account has active access keys | Critical | 1.4 |
| IAM | Password policy below minimum requirements | Medium | 1.8–1.11 |
| IAM | Access key older than 90 days | Medium | 1.14 |
| EC2/SG | SSH (port 22) open to 0.0.0.0/0 | Critical | 5.2 |
| EC2/SG | RDP (port 3389) open to 0.0.0.0/0 | Critical | 5.3 |
| EC2/SG | Database ports open to internet | High | 5.x |
| EC2/SG | All traffic allowed (protocol -1) | Critical | 5.x |
| EC2/SG | Default security group has inbound rules | Medium | 5.4 |
| CloudTrail | No trail exists | Critical | 3.1 |
| CloudTrail | Trail is not multi-region | High | 3.1 |
| CloudTrail | Log file validation disabled | Medium | 3.2 |
| CloudTrail | Not integrated with CloudWatch Logs | Medium | 3.4 |
| CloudTrail | Log bucket is publicly accessible | Critical | 3.3 |
| CloudTrail | Logging currently paused | Critical | 3.1 |

### Auto-Remediation

The Remediator Lambda auto-fixes findings that are safe to correct programmatically:

| Finding | Action Taken |
|---|---|
| S3 public access enabled | Enables all 4 Block Public Access settings |
| S3 versioning disabled | Enables versioning |
| SSH/RDP open to internet | Revokes the specific inbound rule |
| All-traffic SG rule | Revokes the open-world inbound rule |
| IAM / CloudTrail findings | Logged for human review — not auto-fixed |

A `DRY_RUN` mode lets you observe what would be fixed without making any changes. Every remediation action is written to an audit report in S3.

### Compliance Score

After each scan, a compliance score (0–100) is computed and pushed to CloudWatch as a custom metric:

```
Score = (Passed Checks / Total Checks) × 100
```

Track your score trend over time on the CloudWatch dashboard.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Python 3.11 |
| Cloud | AWS Lambda, EventBridge, S3, SNS, CloudWatch, IAM, EC2, CloudTrail |
| IaC | Terraform |
| CI/CD | GitHub Actions |
| SDK | boto3 |
| Testing | pytest |
| Linting | ruff |

---

## Project Structure

```
cspm/
├── scanner/
│   ├── models.py               # Finding dataclass
│   ├── scanner.py              # Scanner Lambda handler
│   └── checks/
│       ├── s3_checks.py        # 4 S3 checks
│       ├── iam_checks.py       # 4 IAM checks
│       ├── sg_checks.py        # 9+ Security Group checks
│       └── cloudtrail_checks.py # 6 CloudTrail checks
├── remediator/
│   ├── remediator.py           # Remediator Lambda handler + dispatcher
│   └── actions/
│       ├── s3_actions.py       # S3 fix functions
│       └── sg_actions.py       # Security Group fix functions
├── infrastructure/
│   ├── main.tf                 # Provider + data sources
│   ├── variables.tf            # Input variables
│   ├── s3.tf                   # Findings bucket
│   ├── sns.tf                  # Alert topic + email subscription
│   ├── iam.tf                  # Least-privilege IAM roles
│   ├── lambda.tf               # Lambda functions + zip packaging
│   ├── eventbridge.tf          # Scheduled trigger
│   ├── outputs.tf              # Useful post-deploy outputs
│   └── terraform.tfvars.example
├── tests/
│   └── test_models.py
├── .github/workflows/
│   └── pipeline.yml            # CI (lint+test) + CD (terraform deploy)
└── requirements.txt
```

---

## Deploy

### Prerequisites

- AWS account (Free Tier is sufficient)
- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.5
- Python 3.11+
- AWS CLI configured (`aws configure`)

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/UTKARSH698/CSPM.git
cd CSPM/infrastructure

# 2. Copy and fill in your variables
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars — set alert_email and aws_region

# 3. Deploy
terraform init
terraform apply

# 4. Confirm the SNS subscription email AWS sends you

# 5. Trigger a manual scan to verify
aws lambda invoke \
  --function-name cspm-scanner \
  --region us-east-1 \
  /tmp/result.json && cat /tmp/result.json
```

### GitHub Actions CI/CD

Every push to `main` automatically lints, tests, and deploys.

Add these secrets to your repo (`Settings → Secrets → Actions`):

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `AWS_REGION` | e.g. `us-east-1` |
| `ALERT_EMAIL` | Email to receive security alerts |

---

## Design Decisions

**DRY_RUN by default** — The remediator deploys with `DRY_RUN=true`. It logs every fix it would make without touching anything. Switch to `false` only after you've reviewed the findings and are confident in the automation.

**Async remediation** — The scanner invokes the remediator with `InvocationType=Event` (fire-and-forget). The scanner never blocks waiting for remediation, keeping scan latency low.

**IAM/CloudTrail not auto-fixed** — Automatically rotating access keys or modifying trail configs carries too much risk of breaking production systems. These findings are flagged for human review.

**IPv4 + IPv6 checked** — Security group checks cover both `0.0.0.0/0` and `::/0`. A common gap in similar tools.

**Port range awareness** — A rule allowing TCP `0–65535` still triggers the SSH check. Most tools only check for exact port matches.

**Least-privilege IAM** — Scanner can only read. Remediator can only modify the specific resources it fixes. Neither has admin access.

---

## AWS Free Tier Usage

| Service | Usage | Free Limit |
|---|---|---|
| Lambda | 2 invocations/hour | 1M req/month |
| EventBridge | 1 event/hour | 1M events/month |
| S3 | ~1 KB JSON per scan | 5 GB |
| CloudWatch | 1 metric per scan | 3 dashboards, 10 metrics |
| SNS | Email on critical findings | 1M publishes/month |

**Estimated monthly cost: $0**

---

## Author

**Utkarsh** — B.Tech CSE (Cloud Technology & Information Security)

- GitHub: [@UTKARSH698](https://github.com/UTKARSH698)
