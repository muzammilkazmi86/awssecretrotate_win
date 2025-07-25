output "secrets" {
  description = "Information about created secrets"
  value = {
    for instance in var.instances : instance.secret_name => {
      secret_arn    = aws_secretsmanager_secret.windows_password[instance.secret_name].arn
      secret_name   = aws_secretsmanager_secret.windows_password[instance.secret_name].name
      instance_id   = instance.instance_id
    }
  }
}

output "lambda_function_name" {
  description = "Name of the rotation Lambda function"
  value       = aws_lambda_function.password_rotation.function_name
}

output "lambda_function_arn" {
  description = "ARN of the rotation Lambda function"
  value       = aws_lambda_function.password_rotation.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for Lambda function"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "rotation_schedule_days" {
  description = "Password rotation schedule in days"
  value       = var.rotation_schedule
}

output "managed_instances" {
  description = "List of managed Windows instances"
  value = [
    for instance in var.instances : {
      instance_id      = instance.instance_id
      secret_name      = instance.secret_name
      windows_username = instance.windows_username
    }
  ]
}