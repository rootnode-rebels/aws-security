"""
Sync Super Admin Credentials to AWS Secrets Manager & SSM Parameter Store.
Encrypts secrets at rest using AWS KMS with zero command-line leakage.
"""
import os
import sys
import json

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import boto3
from botocore.exceptions import ClientError

REGION = os.getenv("AWS_REGION", "eu-north-1")

def get_admin_credentials():
    """Dynamically loads credentials from environment without hardcoding secrets."""
    creds = {}
    ad_pwd = os.getenv("SUPER_ADMIN_PASSWORD_ADHIAM") or os.getenv("SUPER_ADMIN_PASSWORD")
    if ad_pwd:
        creds["adhiam@outlook.in"] = ad_pwd
    anu_pwd = os.getenv("SUPER_ADMIN_PASSWORD_ANUSHREE") or os.getenv("SUPER_ADMIN_PASSWORD")
    if anu_pwd:
        creds["anushree2k5@gmail.com"] = anu_pwd
    return creds

def sync_to_aws_secrets_manager():
    client = boto3.client("secretsmanager", region_name=REGION)
    secret_name = "awssecurity/superadmin/credentials"
    creds = get_admin_credentials()
    if not creds:
        print("[AWS Secrets Manager] No credentials found in environment. Skipping sync.")
        return
    secret_payload = json.dumps(creds)

    print(f"[AWS Secrets Manager] Syncing credentials to secret '{secret_name}' in region '{REGION}'...")
    try:
        res = client.create_secret(
            Name=secret_name,
            Description="Super Admin credentials encrypted with AWS KMS",
            SecretString=secret_payload
        )
        print(f"✅ Created secret: {res.get('ARN')}")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("ResourceExistsException", "InvalidRequestException"):
            print("Secret exists, updating secret value...")
            res = client.put_secret_value(
                SecretId=secret_name,
                SecretString=secret_payload
            )
            print(f"✅ Updated secret value: {res.get('ARN')}")
        else:
            print(f"❌ AWS Secrets Manager error: {e}")

def sync_to_ssm_parameter_store():
    creds = get_admin_credentials()
    if not creds:
        return
    client = boto3.client("ssm", region_name=REGION)
    print(f"[AWS SSM] Syncing credentials to encrypted SecureString parameters in region '{REGION}'...")
    for email, pwd in creds.items():
        param_name = f"/app/superadmin/{email.split('@')[0]}"
        try:
            client.put_parameter(
                Name=param_name,
                Description=f"Encrypted password for {email}",
                Value=pwd,
                Type="SecureString",
                Overwrite=True
            )
            print(f"✅ SSM SecureString updated: {param_name}")
        except Exception as e:
            print(f"❌ SSM error for {param_name}: {e}")

if __name__ == "__main__":
    sync_to_aws_secrets_manager()
    sync_to_ssm_parameter_store()
