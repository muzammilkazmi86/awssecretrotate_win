variable "instances" {
  description = "List of Windows instances to manage passwords for"
  type = list(object({
    instance_id      = string
    secret_name      = string
    windows_username = string
  }))
  
  validation {
    condition = length(var.instances) > 0
    error_message = "At least one instance must be specified."
  }
  
  validation {
    condition = alltrue([
      for instance in var.instances : can(regex("^i-[0-9a-f]{8,17}$", instance.instance_id))
    ])
    error_message = "All instance IDs must be valid EC2 instance ID format (e.g., i-1234567890abcdef0)."
  }
  
  validation {
    condition = alltrue([
      for instance in var.instances : can(regex("^[a-zA-Z0-9/_+=.@-]{1,512}$", instance.secret_name))
    ])
    error_message = "All secret names must be 1-512 characters and contain only letters, numbers, and the characters /_+=.@-."
  }
  
  validation {
    condition = alltrue([
      for instance in var.instances : length(instance.windows_username) > 0
    ])
    error_message = "Windows username cannot be empty for any instance."
  }
}

variable "rotation_schedule" {
  description = "Rotation schedule in days (1-365)"
  type        = number
  default     = 30
  validation {
    condition     = var.rotation_schedule >= 1 && var.rotation_schedule <= 365
    error_message = "The rotation schedule must be between 1 and 365 days."
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.lambda_timeout >= 60 && var.lambda_timeout <= 900
    error_message = "The Lambda timeout must be between 60 and 900 seconds."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "The log retention days must be a valid CloudWatch Logs retention period."
  }
}

variable "recovery_window_days" {
  description = "Number of days to retain deleted secret for recovery"
  type        = number
  default     = 7
  validation {
    condition     = var.recovery_window_days >= 7 && var.recovery_window_days <= 30
    error_message = "The recovery window must be between 7 and 30 days."
  }
}

variable "log_level" {
  description = "Lambda function log level"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.log_level)
    error_message = "The log level must be one of: DEBUG, INFO, WARNING, or ERROR."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "windows-password-rotation"
    ManagedBy   = "terraform"
  }
}