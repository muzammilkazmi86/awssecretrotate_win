# Define multiple Windows instances to manage
instances = [
  {
    instance_id      = "i-0aee831e0b76d7854"
    secret_name      = "web-server-01-password"
    windows_username = "Administrator"
  #},
  #{
  #  instance_id      = "i-0987654321fedcba0"
  #  secret_name      = "web-server-02-password"
  #  windows_username = "Administrator"
  #},
  #{
  #  instance_id      = "i-abcdef1234567890"
  #  secret_name      = "database-server-password"
  #  windows_username = "dbadmin"
  }
]

# Optional customizations
rotation_schedule    = 30
lambda_timeout      = 300
log_retention_days  = 14
log_level          = "INFO"

# Tags for all resources
tags = {
  Environment = "production"
  Project     = "windows-password-rotation"
  Owner       = "PE-team"
  ManagedBy   = "terraform"
}