# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Create a locals block to handle instances
locals {
  # Create a map for easier iteration
  instances_map = {
    for instance in var.instances : instance.secret_name => instance
  }
}

# IAM Role for Lambda (shared across all instances)
resource "aws_iam_role" "lambda_rotation_role" {
  name = "windows-password-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for Lambda (covers all secrets)
resource "aws_iam_role_policy" "lambda_rotation_policy" {
  name = "windows-password-rotation-policy"
  role = aws_iam_role.lambda_rotation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = [
          for instance in var.instances : 
          "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${instance.secret_name}*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:GetPasswordData",
          "ec2:ModifyInstanceAttribute"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:DescribeInstanceInformation"
        ]
        Resource = "*"
      }
    ]
  })
}

# Security Group removed - not needed without VPC configuration

# CloudWatch Log Group (shared)
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/windows-password-rotation"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# Archive file for Lambda deployment
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/password_rotation.zip"
  source_file = "${path.module}/lambda_function.py"
}

# Lambda function for password rotation (shared across all instances)
resource "aws_lambda_function" "password_rotation" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "windows-password-rotation"
  role            = aws_iam_role.lambda_rotation_role.arn
  handler         = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime         = "python3.9"
  timeout         = var.lambda_timeout

  # No VPC configuration - Lambda runs in AWS managed VPC

  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current.name}.amazonaws.com"
      LOG_LEVEL               = var.log_level
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda_rotation_policy,
    aws_cloudwatch_log_group.lambda_logs,
  ]

  tags = var.tags
}

# Lambda permissions for Secrets Manager (one per secret)
resource "aws_lambda_permission" "secrets_manager" {
  for_each = local.instances_map

  statement_id  = "AllowExecutionFromSecretsManager-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.password_rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
  source_arn    = aws_secretsmanager_secret.windows_password[each.key].arn
}

# Secrets Manager Secrets (one per instance)
resource "aws_secretsmanager_secret" "windows_password" {
  for_each = local.instances_map

  name                    = each.value.secret_name
  description             = "Windows instance password for ${each.value.instance_id}"
  recovery_window_in_days = var.recovery_window_days

  tags = merge(var.tags, {
    InstanceId = each.value.instance_id
  })
}

# Initial secret versions (one per instance)
resource "aws_secretsmanager_secret_version" "windows_password" {
  for_each = local.instances_map

  secret_id = aws_secretsmanager_secret.windows_password[each.key].id
  secret_string = jsonencode({
    username    = each.value.windows_username
    password    = "CHANGE_ME_ON_FIRST_ROTATION"
    instance_id = each.value.instance_id
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Automatic rotation configuration (one per secret)
resource "aws_secretsmanager_secret_rotation" "windows_password" {
  for_each = local.instances_map

  secret_id           = aws_secretsmanager_secret.windows_password[each.key].id
  rotation_lambda_arn = aws_lambda_function.password_rotation.arn

  rotation_rules {
    automatically_after_days = var.rotation_schedule
  }

  depends_on = [aws_lambda_permission.secrets_manager]
}