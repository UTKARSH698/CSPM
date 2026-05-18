# CSPM — Technical Deep Dive

This document covers the architecture decisions, security analysis, formal limitations, and engineering reasoning behind the CSPM system. The main README covers recruiter-readable context; this document is for engineers who want the full picture.

---

## Table of Contents

1. [Remediation Safety Analysis](#1-remediation-safety-analysis)
2. [Threat Model](#2-threat-model)
3. [IAM Policy Design](#3-iam-policy-design)
4. [Design Decisions](#4-design-decisions)
5. [The Open Formal Question](#5-the-open-formal-question)
6. [Scaling Analysis](#6-scaling-analysis)

---

## 1. Remediation Safety Analysis

### Dependency Ordering

CSPM applies remediations in a specific order to avoid creating insecure intermediate states:

1. **Block Public Access first** — before examining bucket policies or ACLs
2. **Security group rules** — revoke one offending rule at a time; never replace the entire SG
3. **IAM** — flagged for human review only; automatic key rotation or trail modification can break production workloads

The dependency-ordered strategy prevents the cases I can construct. It cannot be formally proved complete for all possible concurrent misconfiguration states.

### Why IAM and CloudTrail Are Not Auto-Fixed

Automatically modifying IAM policies can break application workloads that depend on specific permissions. Automatically modifying CloudTrail configuration can break audit pipelines. Both require human review to assess blast radius before applying. The system flags them with explicit remediation instructions rather than applying changes automatically.

### Idempotency Gap

The remediator checks current resource state before writing in most cases, but not all. A Lambda retry after a partial fix can attempt to re-apply an already-applied action. The `s3:PutPublicAccessBlock` call is idempotent by nature; `ec2:RevokeSecurityGroupIngress` raises an error if the rule no longer exists. Production hardening would add a pre-action state check for all operations.

---

## 2. Threat Model

| Threat | Vector | Impact | Mitigation |
|---|---|---|---|
| Scanner over-permission | Scanner role granted admin access | Compromise of scanner → full account access | IAM role scoped to read-only actions on S3, IAM, EC2, CloudTrail only |
| Remediator over-permission | Remediator role granted `s3:*` or `iam:*` | Remediator can delete/modify arbitrary resources | Role scoped to specific write actions: `s3:PutPublicAccessBlock`, `ec2:RevokeSecurityGroupIngress` only |
| Findings bucket exposure | S3 bucket with findings made public | Security scan results visible to attackers | Bucket has public access blocked; no public bucket policy |
| SNS interception | SNS topic subscribed by attacker | Alert emails received by attacker | SNS subscription requires email confirmation; no public topic policy |
| False positive remediation | Scanner misidentifies a legitimate rule as a violation | Service disruption from removing a needed SG rule | DRY_RUN=true by default; human review of findings before enabling live remediation |
| Lambda invocation forgery | Attacker invokes remediator directly with crafted input | Arbitrary resource modification | Remediator is not exposed via API Gateway; invoked only by Scanner via IAM-authorized `InvokeFunction` |

---

## 3. IAM Policy Design

### Scanner Role (read-only)

```json
{
  "Effect": "Allow",
    "Action": [
        "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                    "s3:GetBucketEncryption",
                        "s3:ListAllMyBuckets",
                            "iam:GetAccountSummary",
                                "iam:GetAccountPasswordPolicy",
                                    "iam:ListAccessKeys",
                                        "ec2:DescribeSecurityGroups",
                                            "cloudtrail:DescribeTrails",
                                                "cloudtrail:GetTrailStatus",
                                                    "cloudtrail:GetEventSelectors"
                                                      ],
                                                        "Resource": "*"
                                                        }
                                                        ```

                                                        ### Remediator Role (minimal write)

                                                        ```json
                                                        {
                                                          "Effect": "Allow",
                                                            "Action": [
                                                                "s3:PutPublicAccessBlock",
                                                                    "s3:PutBucketVersioning",
                                                                        "ec2:RevokeSecurityGroupIngress"
                                                                          ],
                                                                            "Resource": "*"
                                                                            }
                                                                            ```

                                                                            Neither role has `iam:*`, `lambda:*`, `ec2:*` (broad), or `s3:DeleteObject`. No cross-service access beyond the minimum required.

                                                                            ---

                                                                            ## 4. Design Decisions

                                                                            ### DRY_RUN by Default

                                                                            The remediator ships in dry-run mode. Every action it would take is logged as a JSON entry in S3 without actually modifying anything. This allows a first-run review of what the system would change before enabling live remediation. This is the correct default for any security automation tool operating on production infrastructure.

                                                                            ### Async Remediator Invocation

                                                                            The scanner calls the remediator with `InvocationType=Event` (fire-and-forget). This means:
                                                                            - Scanner always completes within its timeout regardless of remediation complexity
                                                                            - Remediator failures do not affect scanner results
                                                                            - Remediator has its own execution context and retry policy

                                                                            The trade-off: scanner cannot confirm remediator success. Each remediator run writes an audit log to S3 regardless of outcome — this is the confirmation mechanism.

                                                                            ### Single Zip, Two Lambdas

                                                                            Both Lambda functions share one deployment zip with different handler entry points (`scanner.scanner.handler` and `remediator.remediator.handler`). Benefits: single artifact to version, single CI/CD deploy step, smaller attack surface (no unnecessary library duplication). Trade-off: a vulnerability in a shared dependency affects both functions.

                                                                            ### Point-in-Time vs. Continuous

                                                                            The current design scans hourly. A misconfiguration that appears and is manually corrected within the same hour is invisible. Real-time detection would require an EventBridge rule on CloudTrail API calls — triggering a targeted scan whenever a security-relevant API call occurs (`s3:PutBucketPublicAccessBlock`, `ec2:AuthorizeSecurityGroupIngress`, etc.). This is the correct production architecture; the hourly schedule is a simplification for cost and demo purposes.

                                                                            ---

                                                                            ## 5. The Open Formal Question

                                                                            The remediation safety problem: **can a sequence of individually correct fixes produce a collectively insecure intermediate or final state?**

                                                                            My current strategy (dependency-ordered fixes, one control boundary per scan cycle) prevents the cases I can construct. Specifically:
                                                                            - I cannot construct a scenario where fixing S3 public access before examining IAM policies produces an insecure state
                                                                            - I cannot construct a scenario where revoking one SG rule makes the system less secure than leaving it

                                                                            But I cannot *prove* this holds for all reachable states under k simultaneous misconfigurations.

                                                                            The gap: my argument is by case analysis over the failure modes I could construct, not by exhaustive proof over the state space. Under k simultaneous misconfigurations with interdependent remediation actions:
                                                                            1. Does dependency ordering always produce a safe final state?
                                                                            2. Is there a bound on k beyond which the strategy fails?
                                                                            3. Can a partially completed remediation (interrupted Lambda) produce an exploitable intermediate state?

                                                                            Question (3) is the most practically concerning. If the remediator Lambda is killed mid-execution, some fixes have been applied and others have not. Whether the partial state is more or less secure than the pre-remediation state depends on the specific combination of fixes applied.

                                                                            This is a formal methods question. It motivates applying model checking (TLA+, Alloy) to cloud remediation state machines — the same class of problem that CloudFlow surfaces for SAGA compensation completeness.

                                                                            ---

                                                                            ## 6. Scaling Analysis

                                                                            ### Current Limits

                                                                            - **Single-region** — scanner runs in the configured region only. Resources in other regions are invisible.
                                                                            - **Sequential checks** — each check makes independent boto3 API calls. For accounts with 100+ S3 buckets or 50+ security groups, scan time grows linearly.
                                                                            - **Single Lambda execution context** — all 23 checks run in one Lambda invocation.

                                                                            ### Production Architecture

                                                                            A production-grade CSPM would use:

                                                                            1. **Multi-region aggregator** — a central Lambda that assumes an IAM role in each target account/region, collects findings, and aggregates into a central compliance store.
                                                                            2. **Parallel check execution** — use `concurrent.futures.ThreadPoolExecutor` to run check categories in parallel. S3, IAM, EC2, and CloudTrail checks are independent and can run concurrently.
                                                                            3. **AWS Config integration** — use AWS Config Rules instead of scheduled Lambda for continuous evaluation. Config triggers evaluations on resource change events, not just on a schedule.
                                                                            4. **Finding deduplication** — current implementation generates a new findings report on each scan. A production system would track finding lifecycle: OPEN, ACKNOWLEDGED, RESOLVED, SUPPRESSED — and only alert on new findings.
                                                                            5. **STS AssumeRole for multi-account** — a hub-and-spoke model where the central scanner assumes a read-only role in each spoke account. Each spoke account pre-creates a `cspm-scanner` role with appropriate trust policy.

                                                                            ### Cost Analysis (current)

                                                                            | Service | Usage | Monthly Cost |
                                                                            |---|---|---|
                                                                            | Lambda | 2 invocations/hour = 1,460/month | ~$0 (free tier: 1M/month) |
                                                                            | EventBridge | 1 event/hour = 730/month | ~$0 (free tier: 1M/month) |
                                                                            | S3 | ~10KB per scan × 1,460 = ~14MB | ~$0 (free tier: 5GB) |
                                                                            | CloudWatch | 1 custom metric, 1 dashboard | ~$0 (10 metrics free) |
                                                                            | SNS | Critical alerts only | ~$0 (free tier: 1M publishes) |

                                                                            **Total: ~$0/month** for demo usage. A production multi-account, multi-region deployment with real-time CloudTrail integration would cost ~$5–20/month depending on account count and finding volume.
