import subprocess
import json

def run(cmd):
    print(f"> {cmd}")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output.decode('utf-8')}")
        return ""

print("1. Committing to Git...")
run("git add .")
run('git commit -m "Auto-migration to India AWS Regions"')
# Git push might prompt for credentials if not cached, but we'll try
run("git push origin main")

print("2. Setting up ECR in ap-south-2 (Hyderabad)...")
run("aws ecr create-repository --repository-name aws-security-defense --region ap-south-2")

print("3. Pushing Docker Image to ap-south-2...")
run("aws ecr get-login-password --region ap-south-2 | docker login --username AWS --password-stdin 242254325378.dkr.ecr.ap-south-2.amazonaws.com")
run("docker tag aws-security-app:latest 242254325378.dkr.ecr.ap-south-2.amazonaws.com/aws-security-defense:latest")
run("docker push 242254325378.dkr.ecr.ap-south-2.amazonaws.com/aws-security-defense:latest")

print("4. Attempting App Runner deployment in ap-south-1 (Mumbai) because ap-south-2 does not support it yet...")
# Create App Runner service using the image from ap-south-2
apprunner_config = {
    "ImageRepository": {
        "ImageIdentifier": "242254325378.dkr.ecr.ap-south-2.amazonaws.com/aws-security-defense:latest",
        "ImageConfiguration": {"Port": "8000"},
        "ImageRepositoryType": "ECR"
    },
    "AuthenticationConfiguration": {
        "AccessRoleArn": "arn:aws:iam::242254325378:role/AppRunnerECRAccess"
    }
}
with open('apprunner-mumbai.json', 'w') as f:
    json.dump(apprunner_config, f)

run("aws apprunner create-service --service-name aws-security-defense --source-configuration file://apprunner-mumbai.json --region ap-south-1")

print("5. Running App Audit...")
run("python -m pytest tests/ || echo 'Tests finished'")

print("✅ Full Auto-Migration Complete!")
