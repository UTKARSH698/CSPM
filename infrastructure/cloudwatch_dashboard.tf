resource "aws_cloudwatch_dashboard" "cspm" {
  dashboard_name = "CSPM-Security-Posture"

  dashboard_body = jsonencode({
    widgets = [

      # ── Title ──────────────────────────────────────────────────────────────
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = "# 🔐 CSPM — Cloud Security Posture Management\nAutomated AWS security scanning against **CIS AWS Foundations Benchmark v1.5** · Scans every hour · Auto-remediates critical findings"
        }
      },

      # ── Compliance Score — big number ──────────────────────────────────────
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 6
        height = 6
        properties = {
          title  = "Compliance Score (%)"
          view   = "singleValue"
          metrics = [[
            "CSPM", "ComplianceScore"
          ]]
          period = 3600
          stat   = "Maximum"
          region = var.aws_region
        }
      },

      # ── Compliance Score — trend line ──────────────────────────────────────
      {
        type   = "metric"
        x      = 6
        y      = 2
        width  = 18
        height = 6
        properties = {
          title  = "Compliance Score Trend (last 7 days)"
          view   = "timeSeries"
          metrics = [[
            "CSPM", "ComplianceScore",
            { "label" = "Score (%)", "color" = "#2ca02c" }
          ]]
          period     = 3600
          stat       = "Maximum"
          region     = var.aws_region
          yAxis = {
            left = { min = 0, max = 100 }
          }
          annotations = {
            horizontal = [
              { value = 80, label = "Target (80%)", color = "#ff7f0e" }
            ]
          }
        }
      },

      # ── Services checked ───────────────────────────────────────────────────
      {
        type   = "text"
        x      = 0
        y      = 8
        width  = 24
        height = 5
        properties = {
          markdown = <<-EOT
            ## What is being scanned every hour

            | Service | Checks | What it looks for |
            |---|---|---|
            | **S3** | 4 checks | Public buckets · Encryption · Versioning · Access logging |
            | **IAM** | 4 checks | Root MFA · Root access keys · Password policy · Key rotation |
            | **Security Groups** | 9+ checks | SSH/RDP open to internet · All-traffic rules · Default SG |
            | **CloudTrail** | 6 checks | Trail exists · Multi-region · Log validation · CloudWatch Logs |

            > Auto-remediation is active for S3 public access and open Security Group rules. IAM and CloudTrail findings require human review.
          EOT
        }
      },

      # ── Lambda invocations ─────────────────────────────────────────────────
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 12
        height = 6
        properties = {
          title  = "Scanner Invocations (last 24 hrs)"
          view   = "timeSeries"
          metrics = [
            [ "AWS/Lambda", "Invocations", "FunctionName", "cspm-scanner",
              { "label" = "Scanner", "color" = "#1f77b4" }
            ],
            [ "AWS/Lambda", "Invocations", "FunctionName", "cspm-remediator",
              { "label" = "Remediator", "color" = "#9467bd" }
            ]
          ]
          period = 3600
          stat   = "Sum"
          region = var.aws_region
        }
      },

      # ── Lambda errors ──────────────────────────────────────────────────────
      {
        type   = "metric"
        x      = 12
        y      = 13
        width  = 12
        height = 6
        properties = {
          title  = "Lambda Errors (last 24 hrs)"
          view   = "timeSeries"
          metrics = [
            [ "AWS/Lambda", "Errors", "FunctionName", "cspm-scanner",
              { "label" = "Scanner errors", "color" = "#d62728" }
            ],
            [ "AWS/Lambda", "Errors", "FunctionName", "cspm-remediator",
              { "label" = "Remediator errors", "color" = "#ff7f0e" }
            ]
          ]
          period = 3600
          stat   = "Sum"
          region = var.aws_region
        }
      }

    ]
  })
}
