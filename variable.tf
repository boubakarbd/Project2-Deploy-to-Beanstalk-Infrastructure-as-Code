variable "alarm_email_endpoint" {
  description = "The email endpoint for alarm notifications."
  type        = string
}

variable "custom_header_value" {
  description = "Custom header value for requests."
  type        = string
}

variable "db_password" {
  description = "The password for the database."
  type        = string
}

variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1"
}

