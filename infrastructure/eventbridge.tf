# ── EventBridge scheduled rule ─────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "scanner_schedule" {
  name                = "cspm-scanner-schedule"
  description         = "Triggers the CSPM scanner on a schedule"
  schedule_expression = var.scan_schedule

  tags = {
    Project = "cspm"
  }
}

resource "aws_cloudwatch_event_target" "scanner" {
  rule      = aws_cloudwatch_event_rule.scanner_schedule.name
  target_id = "cspm-scanner"
  arn       = aws_lambda_function.scanner.arn
}

# Allow EventBridge to invoke the scanner Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scanner_schedule.arn
}
