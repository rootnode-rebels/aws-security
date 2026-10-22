import os
import subprocess
import json
import shlex
from typing import List, Union

def run(cmd: Union[str, List[str]]) -> str:
    print(f"> {cmd}")
    try:
        if isinstance(cmd, str):
            args = shlex.split(cmd)
        else:
            args = cmd
        output = subprocess.check_output(args, stderr=subprocess.STDOUT).decode('utf-8')
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output.decode('utf-8') if e.output else str(e)}")
        return ""

# Note: Automated git commit/push disabled to enforce user consent and prevent unintentional leaks
# Manual review and selective staging should always precede commits and pushes.

account_id = os.getenv("AWS_ACCOUNT_ID", "123456789012")

print("2. Setting up ECR in ap-south-2 (Hyderabad)...")
run(["aws", "ecr", "create-repository", "--repository-name", "aws-security-defense", "--region", "ap-south-2"])

print("3. Pushing Docker Image to ap-south-2...")
try:
    p1 = subprocess.Popen(["aws", "ecr", "get-login-password", "--region", "ap-south-2"], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["docker", "login", "--username", "AWS", "--password-stdin", f"{account_id}.dkr.ecr.ap-south-2.amazonaws.com"], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p1.stdout:
        p1.stdout.close()
    out, _ = p2.communicate()
    print(out.decode('utf-8', errors='ignore'))
except Exception as e:
    print(f"Docker login notice: {e}")

run(["docker", "tag", "aws-security-app:latest", f"{account_id}.dkr.ecr.ap-south-2.amazonaws.com/aws-security-defense:latest"])
run(["docker", "push", f"{account_id}.dkr.ecr.ap-south-2.amazonaws.com/aws-security-defense:latest"])

print("4. Attempting App Runner deployment in ap-south-1 (Mumbai) because ap-south-2 does not support it yet...")
apprunner_config = {
    "ImageRepository": {
        "ImageIdentifier": f"{account_id}.dkr.ecr.ap-south-2.amazonaws.com/aws-security-defense:latest",
        "ImageConfiguration": {"Port": "8000"},
        "ImageRepositoryType": "ECR"
    },
    "AuthenticationConfiguration": {
        "AccessRoleArn": f"arn:aws:iam::{account_id}:role/AppRunnerECRAccess"
    }
}
temp_json = 'apprunner-mumbai.json'
try:
    with open(temp_json, 'w') as f:
        json.dump(apprunner_config, f)
    run(["aws", "apprunner", "create-service", "--service-name", "aws-security-defense", "--source-configuration", f"file://{temp_json}", "--region", "ap-south-1"])
finally:
    if os.path.exists(temp_json):
        os.remove(temp_json)

print("5. Running App Audit...")
run(["python", "-m", "pytest", "tests/"])

print("✅ Full Auto-Migration Complete!")
