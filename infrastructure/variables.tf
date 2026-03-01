variable "aws_region" {
  description = "AWS region to deploy CSPM resources"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that will receive CSPM security alerts via SNS"
  type        = string
}

variable "dry_run" {
  description = "When true, the remediator logs fixes but does not apply them"
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "EventBridge schedule expression for the scanner"
  type        = string
  default     = "rate(1 hour)"
}
