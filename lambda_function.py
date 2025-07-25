import json
import boto3
import logging
import string
import secrets
import time
import os
from botocore.exceptions import ClientError

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logger = logging.getLogger()
logger.setLevel(getattr(logging, log_level))

def lambda_handler(event, context):
    """
    Main Lambda handler for Windows password rotation
    """
    try:
        # Parse the event
        # Extract the secret's Amazon Resource Name from the event. This identifies which secret to rotate.
        secret_arn = event['SecretId']
        # Get the unique token for this rotation attempt. Each rotation gets a new token.
        token = event['ClientRequestToken']
        # Get which step we're executing: "createSecret", "setSecret", "testSecret", or "finishSecret".
        step = event['Step']
        #  Log what we're about to do. This appears in CloudWatch Logs for debugging.
        logger.info(f"Starting rotation step: {step} for secret: {secret_arn}")
        
        # Initialize clients
        # Create a client to talk to AWS Secrets Manager service.
        secrets_client = boto3.client('secretsmanager')
        # Create a client to talk to AWS Secrets Manager service.
        ec2_client = boto3.client('ec2')
        # Create a client to talk to AWS EC2 service (to check instance status).
        ssm_client = boto3.client('ssm')
        
        # Route to appropriate step function
        # Create a client to talk to AWS Systems Manager (to run commands on Windows).
        # create_secret: Call the function to create a new password version.
        # set_secret: Call the function to actually change the password on Windows.
        # test_secret: Call the function to verify the new password works.
        # finish_secret: Call the function to promote the new password to current.
        # ValueError: For unknown error check logs
        if step == "createSecret":
            create_secret(secrets_client, secret_arn, token)
        elif step == "setSecret":
            set_secret(secrets_client, ec2_client, ssm_client, secret_arn, token)
        elif step == "testSecret":
            test_secret(secrets_client, ec2_client, ssm_client, secret_arn, token)
        elif step == "finishSecret":
            finish_secret(secrets_client, secret_arn, token)
        else:
            raise ValueError(f"Invalid step parameter: {step}")
        # Log that the step completed successfully and Return success status to AWS (like HTTP 200 OK).    
        logger.info(f"Successfully completed step: {step}")
        return {"statusCode": 200}
    # If anything failed, log the error and re-raise it so AWS knows the rotation failed.    
    except Exception as e:
        logger.error(f"Error in rotation step {step}: {str(e)}")
        raise e

def create_secret(secrets_client, secret_arn, token):
    """Create a new secret version with a new password"""
    try:
        # Check if this version already exists
        try:
            # Try to get the "pending" version with our token. If this succeeds, we already created it.
            secrets_client.get_secret_value(SecretId=secret_arn, VersionStage="AWSPENDING", VersionId=token)
            logger.info("Secret version already exists for token")
            return
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise e
        
        # Get current secret
        current_secret = secrets_client.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
        current_data = json.loads(current_secret['SecretString'])
        
        # Create a new secure password using our helper function.
        new_password = generate_password()
        
        # Build the new secret data structure with the same username and instance ID, but new password.
        new_secret = {
            "username": current_data.get("username", "Administrator"),
            "password": new_password,
            "instance_id": current_data["instance_id"]
        }
        # Store the new secret version in AWS with the "AWSPENDING" label (not active yet).
        secrets_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps(new_secret),
            VersionStages=['AWSPENDING']
        )
        # Log success.
        logger.info("Successfully created new secret version")
        
    except Exception as e:
        logger.error(f"Error in create_secret: {str(e)}")
        raise e

def set_secret(secrets_client, ec2_client, ssm_client, secret_arn, token):
    """Set the new password on the Windows instance"""
    try:
        # Get the pending secret. Get the new password we created in the previous step.
        pending_secret = secrets_client.get_secret_value(SecretId=secret_arn, VersionStage="AWSPENDING", VersionId=token)
        # Parse the JSON to get username, password, and instance ID.
        secret_data = json.loads(pending_secret['SecretString'])
        # Extract the individual values we need.
        instance_id = secret_data['instance_id']
        new_password = secret_data['password']
        username = secret_data['username']
        
        # Ask EC2 for information about our Windows instance.
        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
        # Extract the instance state (running, stopped, etc.) from the response.
        instance_state = instance_info['Reservations'][0]['Instances'][0]['State']['Name']
        # If instance isn't running, we can't change the password - fail with clear error.
        if instance_state != 'running':
            raise Exception(f"Instance {instance_id} is not running. Current state: {instance_state}")
        
        # Wait for SSM agent to be online and make sure the SSM agent on Windows is ready to receive commands.
        wait_for_ssm_agent(ssm_client, instance_id)
        
        # Change password using PowerShell
        powershell_command = f"""
        $ErrorActionPreference = 'Stop'
        try {{
            $UserAccount = [ADSI]"WinNT://./{username},user"
            $UserAccount.SetPassword('{new_password}')
            $UserAccount.SetInfo()
            Write-Output "Password changed successfully for user {username}"
        }}
        catch {{
            Write-Error "Failed to change password: $($_.Exception.Message)"
            exit 1
        }}
        """
        
        # Execute the command and send the PowerShell script to run on the Windows instance via SSM.
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={'commands': [powershell_command]},
            TimeoutSeconds=60
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command completion to finish and check if it succeeded.
        wait_for_command_completion(ssm_client, command_id, instance_id, "Password change")
        
    except Exception as e:
        logger.error(f"Error in set_secret: {str(e)}")
        raise e

def test_secret(secrets_client, ec2_client, ssm_client, secret_arn, token):
    """Test the new password"""
    try:
        # Get the pending secret (Get the new password and connection details (same as set_secret function).)
        pending_secret = secrets_client.get_secret_value(SecretId=secret_arn, VersionStage="AWSPENDING", VersionId=token)
        secret_data = json.loads(pending_secret['SecretString'])
        
        instance_id = secret_data['instance_id']
        username = secret_data['username']
        
        # Build a PowerShell script to test the password change:
        # Get current user context for debugging
        # Check if the user account exists
        # Verify the account is enabled (not disabled)
        # Report success or failure
        test_command = f"""
        $ErrorActionPreference = 'Stop'
        try {{
            $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            Write-Output "Current user context: $CurrentUser"
            
            # Test local user exists and is enabled
            $User = Get-LocalUser -Name '{username}' -ErrorAction Stop
            if ($User.Enabled -eq $false) {{
                throw "User {username} is disabled"
            }}
            Write-Output "User {username} exists and is enabled"
        }}
        catch {{
            Write-Error "Password test failed: $($_.Exception.Message)"
            exit 1
        }}
        """
        # Send the test script to run on Windows
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={'commands': [test_command]},
            TimeoutSeconds=60
        )
        # Wait for test to complete and verify it succeeded
        command_id = response['Command']['CommandId']
        wait_for_command_completion(ssm_client, command_id, instance_id, "Password test")
    # Error handling    
    except Exception as e:
        logger.error(f"Error in test_secret: {str(e)}")
        raise e

def finish_secret(secrets_client, secret_arn, token):
    """Finish the rotation by updating version stages"""
    try:
        # Get the current secret to get metadata about the secret, including which versions have which labels.
        current_secret = secrets_client.describe_secret(SecretId=secret_arn)
        
        # Find the version that currently has AWSCURRENT label by looping through all versions
        current_version_id = None
        for version_id, version_info in current_secret['VersionIdsToStages'].items():
            if 'AWSCURRENT' in version_info:
                current_version_id = version_id
                break
        # If we can't find the current version, something's wrong - fail with error
        if not current_version_id:
            raise Exception("Could not find current version with AWSCURRENT label")
        
        # Move AWSCURRENT from old version to new version to make the new PW active
        # and move AWSPENDING to AWSCURRENT on the new version
        secrets_client.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version_id
        )
        # logging successful label move
        logger.info(f"Successfully moved AWSCURRENT from {current_version_id} to {token}")
        
        # (This is why initial rotations failed) Clean up by removing the "AWSPENDING" label from the new current version.
        try:
            secrets_client.update_secret_version_stage(
                SecretId=secret_arn,
                VersionStage="AWSPENDING",
                RemoveFromVersionId=token
            )
            logger.info("Successfully removed AWSPENDING stage from new current version")
        except ClientError as e:
            # This might fail if AWSPENDING was already removed, which is okay
            if e.response['Error']['Code'] != 'InvalidParameterException':
                logger.warning(f"Could not remove AWSPENDING stage: {e}")
        # Log overall success
        logger.info("Successfully finished secret rotation")
        
    except Exception as e:
        logger.error(f"Error in finish_secret: {str(e)}")
        raise e

def generate_password(length=16):
    """Generate a secure random password"""
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*"
    
    # Start the password with one character from each set to meet typical password complexity requirements.
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]
    
    # Fill the remaining characters randomly from all character sets.
    all_chars = lowercase + uppercase + digits + special_chars
    for _ in range(length - 4):
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

def wait_for_ssm_agent(ssm_client, instance_id, max_wait_time=300):
    """Wait for SSM agent to be online"""
    # Documentation and record when we started waiting, this was the other issue causing rotation to not fail in logs but fail on system
    start_time = time.time()
    # Keep looping until we timeout.
    while time.time() - start_time < max_wait_time:
        try:
            # Ask SSM for information about our instance.
            response = ssm_client.describe_instance_information(
                InstanceInformationFilterList=[
                    {'key': 'InstanceIds', 'valueSet': [instance_id]}
                ]
            )
            #  If we got instance info and the ping status is "Online", the agent is ready.
            if response['InstanceInformationList']:
                instance_info = response['InstanceInformationList'][0]
                if instance_info['PingStatus'] == 'Online':
                    logger.info(f"SSM agent is online for instance {instance_id}")
                    return True
        # If we get an error checking status, log it but keep trying.    
        except ClientError as e:
            logger.warning(f"Error checking SSM agent status: {e}")
        # Wait 10 seconds before checking again.
        time.sleep(10)
    # If we timeout, raise an error.
    raise Exception(f"SSM agent did not come online within {max_wait_time} seconds")

def wait_for_command_completion(ssm_client, command_id, instance_id, operation_name, max_attempts=30):
    """Wait for SSM command to complete"""
    # Function to wait for an SSM command to finish. Tries 30 times (60 seconds total).
    for attempt in range(max_attempts):
        time.sleep(2)
        try:
            # Check the status of our command.
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            # Check the command status:
            # If "Success", we're done
            # If failed/cancelled/timed out, raise an error with details
            status = result['Status']
            if status == 'Success':
                logger.info(f"{operation_name} successful on {instance_id}")
                return result
            elif status in ['Failed', 'Cancelled', 'TimedOut']:
                error_output = result.get('StandardErrorContent', 'No error details available')
                raise Exception(f"{operation_name} failed with status {status}: {error_output}")
        # If we get "InvocationDoesNotExist", the command is still running - keep waiting.        
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvocationDoesNotExist':
                # Command still running
                continue
            raise e
    #  If we exhaust all attempts, raise a timeout error.
    raise Exception(f"{operation_name} timed out after {max_attempts * 2} seconds")