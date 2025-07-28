# Windows EC2 Password Rotation System

Automated Terraform solution for rotating Windows EC2 local administrator passwords using AWS Lambda, Secrets Manager, and Systems Manager.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Security](#security)

## Overview

This solution automatically rotates Windows instance passwords on a configurable schedule, eliminating manual password management while maintaining security compliance.

### Benefits
- **Zero-downtime rotation** with automatic rollback capability
- **Multi-instance support** from single deployment
- **Secure storage** with encrypted AWS Secrets Manager
- **Complete audit trail** via CloudWatch logging
- **Compliance ready** for SOX

### Architecture

```
Secrets Manager ──► Lambda Function ──► Windows EC2
      │                    │                 │
      ▼                    ▼                 ▼
 CloudWatch Logs     IAM Roles        SSM Agent
```

**4-Step Rotation Process:**
1. **Create** - Generate new secure password
2. **Set** - Change password on Windows via PowerShell
3. **Test** - Verify new password functionality
4. **Finish** - Promote new password to current

## Prerequisites

### AWS Requirements
- AWS CLI configured with admin permissions
- Terraform 0.15+ installed
- Windows EC2 instances with SSM Agent (pre-installed on modern AMIs)

### Windows Instance Setup
Instances need IAM instance profile with `AmazonSSMManagedInstanceCore` policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "ssm:UpdateInstanceInformation",
            "ssm:SendCommand",
            "ssm:GetCommandInvocation"
        ],
        "Resource": "*"
    }]
}
```
### To install SSM while EC2 Windows is being deployed

Add the following script the the User data section:

```bash
<powershell>
$dir = $env:TEMP + "\ssm"
New-Item -ItemType directory -Path $dir -Force
cd $dir
(New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe", $dir + "\AmazonSSMAgentSetup.exe")
Start-Process .\AmazonSSMAgentSetup.exe -ArgumentList @("/q", "/log", "install.log") -Wait
</powershell>
```
## Installation

1. **Create project directory:**
```bash
mkdir windows-password-rotation && cd windows-password-rotation
```

2. **Create required files:**
```
├── main.tf
├── variables.tf  
├── outputs.tf
├── versions.tf
├── lambda_function.py
├── terraform.tfvars
└── README.md
```

3. **Initialize Terraform:**
```bash
terraform init
```

## Configuration

Edit `terraform.tfvars` with your instances:

```hcl
instances = [
  {
    instance_id      = "i-1234567890abcdef0"
    secret_name      = "web-server-01-password"
    windows_username = "Administrator"
  },
  {
    instance_id      = "i-0987654321fedcba0"
    secret_name      = "db-server-password"
    windows_username = "dbadmin"
  }
]

rotation_schedule   = 30  # Days between rotations
lambda_timeout      = 300 # Seconds
log_retention_days  = 14
log_level          = "INFO"

tags = {
  Environment = "production"
  Project     = "password-rotation"
  Owner       = "security-team"
}
```

### Key Variables
- **instance_id**: EC2 instance identifier
- **secret_name**: Unique name for Secrets Manager secret
- **windows_username**: Local Windows account to rotate
- **rotation_schedule**: Days between automatic rotations (1-365)

## Deployment

1. **Validate configuration:**
```bash
terraform validate
terraform plan
```

2. **Deploy infrastructure:**
```bash
terraform apply
```

3. **Set initial passwords:**
```bash
aws secretsmanager put-secret-value \
    --secret-id "web-server-01-password" \
    --secret-string '{
        "username": "Administrator",
        "password": "CurrentPassword123!",
        "instance_id": "i-1234567890abcdef0"
    }'
```

4. **Test rotation:**
```bash
aws secretsmanager rotate-secret --secret-id "web-server-01-password"
```

## Operations

### Monitoring

**CloudWatch Logs:** `/aws/lambda/windows-password-rotation`

**Key log messages:**
```
INFO: Starting rotation step: createSecret
INFO: Password changed successfully for user Administrator  
INFO: Successfully finished secret rotation
```

**Check rotation status:**
```bash
aws secretsmanager list-secrets \
    --query 'SecretList[?RotationEnabled==`true`].[Name,NextRotationDate]' \
    --output table
```

### Password Retrieval

**Get current password:**
```bash
aws secretsmanager get-secret-value \
    --secret-id "web-server-01-password" \
    --query 'SecretString' --output text | jq -r '.password'
```

**Get previous password (emergency):**
```bash
aws secretsmanager get-secret-value \
    --secret-id "web-server-01-password" \
    --version-stage AWSPREVIOUS
```

## Troubleshooting

### Common Issues

**SSM Agent Offline:**
```
ERROR: SSM agent did not come online within 300 seconds
```
**Solutions:**
- Verify instance is running
- Check internet connectivity
- Restart SSM service: `Restart-Service AmazonSSMAgent`

**Password Policy Violations:**
```
ERROR: Password does not meet policy requirements
```
**Solutions:**
- Review Windows local security policy
- Modify `generate_password()` function in `lambda_function.py`

**Lambda Timeout:**
```
ERROR: Task timed out after 300 seconds
```
**Solutions:**
- Increase `lambda_timeout` in `terraform.tfvars`
- Check network connectivity

### Diagnostic Commands

**Test SSM connectivity:**
```bash
aws ssm send-command \
    --instance-ids i-1234567890abcdef0 \
    --document-name "AWS-RunPowerShellScript" \
    --parameters 'commands=["Get-Date"]'
```

**View Lambda logs:**
```bash
aws logs describe-log-streams \
    --log-group-name "/aws/lambda/windows-password-rotation" \
    --order-by LastEventTime --descending --max-items 1
```

## Security

### Encryption
- **At Rest**: All secrets encrypted with AWS KMS
- **In Transit**: TLS 1.2+ for all communications
- **Password Generation**: Cryptographically secure 16-character passwords

### Access Control
- **Least Privilege**: Lambda has minimal required permissions
- **Resource Scoped**: IAM policies limited to specific secrets
- **Audit Trail**: Complete CloudTrail and CloudWatch logging

### Password Security
- **Complexity**: Uppercase, lowercase, digits, special characters
- **No Logging**: Passwords never appear in logs
- **Version History**: Previous passwords retained for rollback

### Compliance Features
- **Audit Logging**: Complete operation history
- **Access Controls**: IAM-based secret access
- **Encryption**: End-to-end encryption
- **Rotation Tracking**: Detailed rotation timestamps

## Cost Analysis

**Monthly costs (10 instances): For my sample lab**
- Lambda: ~$1.00
- Secrets Manager: ~$4.00 
- CloudWatch Logs: ~$2.00
- **Total: ~$7.00/month**

**ROI Comparison:  For my sample lab**
- Manual rotation: 100+ hours annually
- Automated: <5 hours setup + monitoring

## Advanced Features

### Custom Password Policy
Modify `lambda_function.py`:
```python
def generate_password(length=20):
    # Custom complexity requirements
    special_chars = "!@#$%^&*()_+-="
    # Implementation here
```

### Multi-Region Deployment
Deploy across regions for disaster recovery by updating `versions.tf` provider configuration.

### Integration Options
- **ServiceNow**: Webhook notifications for change management
- **Slack**: Rotation status alerts
- **CloudWatch Alarms**: Automated failure notifications

## File Structure

The complete solution includes these files:

- `main.tf` - Main Terraform configuration
- `variables.tf` - Variable definitions with validation
- `outputs.tf` - Deployment outputs
- `versions.tf` - Provider requirements
- `lambda_function.py` - Password rotation logic
- `terraform.tfvars` - Your configuration values

## Support

**Resources:**
- AWS Systems Manager documentation
- AWS Secrets Manager rotation guide
- Terraform AWS provider documentation

**Common Support Scenarios:**
- Lambda function debugging via CloudWatch Logs
- SSM connectivity issues with EC2 instances
- IAM permission troubleshooting
- Password policy customization

---

**Version:** 1.0  
**Last Updated:** July 2025
