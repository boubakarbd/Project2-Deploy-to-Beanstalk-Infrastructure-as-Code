variable "db_password" {
  type        = string
  description = "The password for the RDS database instance"
}

variable "custom_header_value" {
  type        = string
  description = "The value for the custom header to be added by CloudFront" 
}

variable "alarm_email_endpoint" {
  type        = string
  description = "The email address to receive CloudWatch alarm notifications"
}