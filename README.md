<div align="center">

# CSPM

### Cloud Security Posture Management — AWS Security Automation

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Terraform](https://img.shields.io/badge/Terraform-IaC-7B42BC?style=flat-square&logo=terraform&logoColor=white)](https://terraform.io)
[![Tests](https://img.shields.io/badge/Tests-64_passing-brightgreen?style=flat-square)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

---

## What This Project Demonstrates

- **Security automation pipeline** — EventBridge triggers Lambda hourly; scanner audits 4 AWS services; auto-remediator fixes safe issues; compliance score published to CloudWatch.
- - **23 CIS AWS Foundations Benchmark checks** — mapped to CIS v1.5 across S3, IAM, EC2/Security Groups, and CloudTrail.
  - - **Auto-remediation** — S3 Block Public Access, bucket versioning, and open security group rules are fixed programmatically. IAM/CloudTrail issues flagged for human review (too risky to auto-apply).
    - - **Port-range aware SG checks** — a rule allowing TCP 0–65535 still triggers the SSH check. Most tools match exact port numbers only.
      - - **IPv4 + IPv6 coverage** — `0.0.0.0/0` and `::/0` both checked. Most tools miss IPv6.
        - - **64 tests** using moto to mock AWS APIs — no credentials needed, runs in < 5 seconds.
          - - **Compliance scoring** — `(passed / total) × 100` pushed as a CloudWatch custom metric with 7-day trend dashboard.
           
            - ---

            ## Architecture

            ```
            EventBridge (hourly)
                    │
                    ▼
            ┌───────────────┐     audits     ┌──────────────────────────┐
            │ Scanner λ     │ ─────────────► │ S3 · IAM · EC2 · CT APIs │
            └───────┬───────┘                └──────────────────────────┘
                    │
               ┌────┼────────────────────────────────┐
               ▼    ▼                ▼               ▼
              S3  CloudWatch       SNS           Remediator λ
            findings  score      critical          │
            (JSON)  metric       alerts     ┌──────┴──────────┐
                                            ▼                  ▼
                                     S3 public access    Open SG rules
                                     auto-fixed          removed
                                     (audit log to S3)
            ```

            **Flow:** Scanner audits → findings saved to S3 → compliance score pushed to CloudWatch → critical findings trigger SNS email → scanner asynchronously invokes Remediator (fire-and-forget) → Remediator fixes safe issues and logs the rest.

            ---

            ## Security Checks (23 checks, CIS AWS Foundations Benchmark v1.5)

            | Service | Checks | Critical Findings |
            |---|---|---|
            | S3 | Block Public Access, versioning, access logging, default encryption | S3-001: public access enabled |
            | IAM | Root MFA, root access keys, password policy, key age | IAM-001/002: root account exposure |
            | EC2 / Security Groups | SSH, RDP, MySQL, Postgres, MongoDB, Redis, Elasticsearch, all-traffic, default SG | SG-22/3389: internet-exposed admin ports |
            | CloudTrail | Trail exists, multi-region, log validation, CloudWatch integration, public bucket, logging paused | CT-001: no trail; CT-005: logs publicly accessible |

            ---

            ## Auto-Remediation

            | Finding | Action |
            |---|---|
            | S3 Block Public Access disabled | Enables all 4 Block Public Access settings |
            | S3 versioning disabled | Enables versioning |
            | SSH / RDP open to internet | Revokes the specific offending inbound rule |
            | All-traffic SG rule | Removes the open-world inbound rule |
            | IAM / CloudTrail issues | Logged for human review — auto-fix too risky |

            `DRY_RUN=true` by default — logs every action it would take without touching anything. Set `DRY_RUN=false` after reviewing your first scan.

            ---

            ## Compliance Score Example

            ```
            Scan 1 — new account, no config:    66.7%  ████████████████████░░░░░░░░░░
            Scan 2 — CloudTrail created:        68.0%  ████████████████████░░░░░░░░░░
            Scan 3 — IAM + SG + CT fixed:       76.0%  ██████████████████████░░░░░░░░
            Scan 4 — CloudWatch Logs linked:    80.0%  ████████████████████████░░░░░░
            ```

            ---

            ## Tech Stack

            `Python 3.11` `AWS Lambda` `EventBridge` `S3` `SNS` `CloudWatch` `IAM` `EC2` `CloudTrail` `Terraform` `pytest` `moto` `GitHub Actions`

            ---

            ## Engineering Highlights

            **Async remediation** — Scanner invokes Remediator with `InvocationType=Event` (fire-and-forget). Scanner latency stays under 6 seconds regardless of how many issues need fixing.

            **Single zip, two Lambdas** — both functions share one deployment package with different handler paths. Simpler packaging, smaller attack surface.

            **IAM least-privilege** — Scanner role: read-only on S3, IAM, EC2, CloudTrail. Remediator role: only the specific write actions it needs. Neither has admin permissions or cross-service access.

            **The open formal question** — whether a sequence of individually correct fixes can produce a collectively insecure intermediate state is the core unsolved problem this project surfaces. Dependency-ordered remediation prevents the cases I can construct, but formal completeness requires a model of the remediation state space. See [TECHNICAL.md](TECHNICAL.md).

            ---

            ## Quick Start

            ```bash
            git clone https://github.com/UTKARSH698/CSPM
            cd CSPM/infrastructure

            cp terraform.tfvars.example terraform.tfvars
            # Set alert_email and aws_region

            terraform init
            terraform apply

            # Run first scan
            aws lambda invoke --function-name cspm-scanner --region us-east-1 result.json
            cat result.json
            ```

            **Run tests (no AWS credentials needed):**
            ```bash
            pip install pytest boto3 "moto[s3,iam,ec2,cloudtrail]"
            pytest tests/ -v --cov=scanner --cov=remediator
            ```

            ---

            ## Project Structure

            ```
            cspm/
            ├── scanner/
            │   ├── scanner.py          # Lambda handler — orchestrates all checks
            │   └── checks/
            │       ├── s3_checks.py    # 4 checks
            │       ├── iam_checks.py   # 4 checks
            │       ├── sg_checks.py    # 9 checks
            │       └── cloudtrail_checks.py  # 6 checks
            ├── remediator/
            │   ├── remediator.py
            │   └── actions/
            │       ├── s3_actions.py
            │       └── sg_actions.py
            ├── infrastructure/         # Terraform — ~19 AWS resources
            │   ├── lambda.tf
            │   ├── eventbridge.tf
            │   ├── cloudwatch_dashboard.tf
            │   └── iam.tf
            ├── tests/                  # 64 tests, moto mocks
            ├── TECHNICAL.md            # Remediation safety analysis, threat model, formal question
            └── .github/workflows/      # CI: lint + test on PR | deploy on merge
            ```

            ---

            ## Known Limitations

            - Single-region only — no cross-region aggregation
            - - No real-time drift detection between scans (point-in-time only)
              - - Remediation not formally proved complete under all concurrent misconfiguration states
                - - Remediator not idempotent across Lambda retries for all action types
                 
                  - See **[TECHNICAL.md](TECHNICAL.md)** for the full formal analysis.
                 
                  - ---

                  *MIT License · Utkarsh Batham*
