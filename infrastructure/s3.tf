# ── Findings bucket ────────────────────────────────────────────────────────────
# Stores: findings JSON + remediation reports

resource "aws_s3_bucket" "findings" {
  bucket = "cspm-findings-${data.aws_caller_identity.current.account_id}"

  tags = {
    Project = "cspm"
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket = aws_s3_bucket.findings.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Auto-delete old findings after 90 days to keep the bucket within free tier
resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    id     = "expire-findings"
    status = "Enabled"

    filter {
      prefix = "findings/"
    }

    expiration {
      days = 90
    }
  }

  rule {
    id     = "expire-reports"
    status = "Enabled"

    filter {
      prefix = "remediation-reports/"
    }

    expiration {
      days = 90
    }
  }
}
