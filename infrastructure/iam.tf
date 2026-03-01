# ── Shared Lambda assume-role policy ──────────────────────────────────────────

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ── Scanner IAM role ───────────────────────────────────────────────────────────

resource "aws_iam_role" "scanner" {
  name               = "cspm-scanner-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "scanner" {
  name   = "cspm-scanner-policy"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner_policy.json
}

data "aws_iam_policy_document" "scanner_policy" {
  # CloudWatch Logs (Lambda execution logs)
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Store findings in S3
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.findings.arn}/*"]
  }

  # Publish compliance score metric
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
  }

  # Send alert emails
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  # Invoke remediator asynchronously
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.remediator.arn]
  }

  # S3 checks — read bucket configurations
  statement {
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketVersioning",
      "s3:GetBucketLogging",
      "s3:GetEncryptionConfiguration",
    ]
    resources = ["*"]
  }

  # IAM checks
  statement {
    actions = [
      "iam:GetAccountSummary",
      "iam:GetAccountPasswordPolicy",
      "iam:ListUsers",
      "iam:ListAccessKeys",
    ]
    resources = ["*"]
  }

  # Security Group checks
  statement {
    actions   = ["ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }

  # CloudTrail checks
  statement {
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
    ]
    resources = ["*"]
  }
}

# Attach AWS managed basic execution policy
resource "aws_iam_role_policy_attachment" "scanner_basic" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


# ── Remediator IAM role ────────────────────────────────────────────────────────

resource "aws_iam_role" "remediator" {
  name               = "cspm-remediator-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "remediator" {
  name   = "cspm-remediator-policy"
  role   = aws_iam_role.remediator.id
  policy = data.aws_iam_policy_document.remediator_policy.json
}

data "aws_iam_policy_document" "remediator_policy" {
  # CloudWatch Logs
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Save remediation reports
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.findings.arn}/*"]
  }

  # S3 auto-remediation — fix public buckets
  statement {
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetPublicAccessBlock",
      "s3:PutBucketVersioning",
    ]
    resources = ["*"]
  }

  # SG auto-remediation — revoke open rules
  statement {
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:RevokeSecurityGroupIngress",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "remediator_basic" {
  role       = aws_iam_role.remediator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
