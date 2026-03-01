# ── Package source code into a single zip ─────────────────────────────────────
# Both Lambdas share the same zip — they use different handler paths.

data "archive_file" "cspm" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  excludes = [
    "infrastructure",
    "dashboard",
    "tests",
    ".github",
    "requirements.txt",
    "**/__pycache__",
    "**/*.pyc",
  ]
  output_path = "${path.module}/cspm.zip"
}


# ── Scanner Lambda ─────────────────────────────────────────────────────────────

resource "aws_lambda_function" "scanner" {
  function_name    = "cspm-scanner"
  role             = aws_iam_role.scanner.arn
  runtime          = "python3.11"
  handler          = "scanner.scanner.lambda_handler"
  timeout          = 300   # 5 minutes — scans can take time on large accounts
  memory_size      = 256

  filename         = data.archive_file.cspm.output_path
  source_code_hash = data.archive_file.cspm.output_base64sha256

  environment {
    variables = {
      FINDINGS_BUCKET     = aws_s3_bucket.findings.bucket
      SNS_TOPIC_ARN       = aws_sns_topic.alerts.arn
      REMEDIATOR_FUNCTION = aws_lambda_function.remediator.function_name
    }
  }

  tags = {
    Project = "cspm"
  }
}


# ── Remediator Lambda ──────────────────────────────────────────────────────────

resource "aws_lambda_function" "remediator" {
  function_name    = "cspm-remediator"
  role             = aws_iam_role.remediator.arn
  runtime          = "python3.11"
  handler          = "remediator.remediator.lambda_handler"
  timeout          = 300
  memory_size      = 256

  filename         = data.archive_file.cspm.output_path
  source_code_hash = data.archive_file.cspm.output_base64sha256

  environment {
    variables = {
      FINDINGS_BUCKET = aws_s3_bucket.findings.bucket
      DRY_RUN         = tostring(var.dry_run)
    }
  }

  tags = {
    Project = "cspm"
  }
}
