# ── SNS topic for CSPM security alerts ────────────────────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "cspm-security-alerts"

  tags = {
    Project = "cspm"
  }
}

# Email subscription — AWS will send a confirmation email on first deploy
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
