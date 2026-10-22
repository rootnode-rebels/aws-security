import subprocess
import json
import sys
import time
import os

arn = os.getenv("APPRUNNER_SERVICE_ARN")
mongodb_uri = os.getenv("MONGODB_URI")
aws_region = os.getenv("AWS_REGION", "eu-central-1")

if not arn:
    print("[ERROR] APPRUNNER_SERVICE_ARN environment variable is required.")
    sys.exit(1)

if not mongodb_uri:
    print("[ERROR] MONGODB_URI environment variable is required.")
    sys.exit(1)

def get_status():
    res = subprocess.check_output(["aws", "apprunner", "describe-service", "--service-arn", arn, "--region", aws_region])
    data = json.loads(res.decode('utf-8'))
    return data['Service']

print("Waiting for any ongoing deployment to finish before updating environment variables...")
while True:
    service = get_status()
    if service['Status'] == "RUNNING":
        break
    print(f"Current status: {service['Status']}")
    time.sleep(15)

print("Service is ready. Injecting MongoDB URI from environment...")
source_config = service['SourceConfiguration']
source_config['ImageRepository']['ImageConfiguration']['RuntimeEnvironmentVariables']['MONGODB_URI'] = mongodb_uri

temp_config_path = 'temp_source_config.json'
try:
    with open(temp_config_path, 'w') as f:
        json.dump(source_config, f)

    subprocess.check_call(["aws", "apprunner", "update-service", "--service-arn", arn, "--region", aws_region, "--source-configuration", f"file://{temp_config_path}"])
    print("✅ MongoDB URI injected! App Runner is redeploying with the cloud database.")
except Exception as e:
    print(f"❌ Failed to update App Runner: {e}")
finally:
    if os.path.exists(temp_config_path):
        os.remove(temp_config_path)
