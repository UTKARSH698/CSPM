output "findings_bucket" {
  description = "S3 bucket storing findings and remediation reports"
  value       = aws_s3_bucket.findings.bucket
}

output "scanner_function_name" {
  description = "Name of the Scanner Lambda function"
  value       = aws_lambda_function.scanner.function_name
}

output "remediator_function_name" {
  description = "Name of the Remediator Lambda function"
  value       = aws_lambda_function.remediator.function_name
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.alerts.arn
}

output "invoke_scanner_now" {
  description = "AWS CLI command to trigger a manual scan"
  value       = "aws lambda invoke --function-name ${aws_lambda_function.scanner.function_name} --region ${var.aws_region} /tmp/scan-result.json && cat /tmp/scan-result.json"
}
