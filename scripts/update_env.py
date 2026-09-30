import subprocess
import json
import sys
import time

arn = "arn:aws:apprunner:eu-central-1:242254325378:service/aws-security-app-service/e2c75827b7fe48a0963c9b0dc69ccc5e"

def get_status():
    res = subprocess.check_output(f"aws apprunner describe-service --service-arn {arn} --region eu-central-1", shell=True)
    data = json.loads(res.decode('utf-8'))
    return data['Service']

print("Waiting for any ongoing deployment to finish before updating environment variables...")
while True:
    service = get_status()
    if service['Status'] == "RUNNING":
        break
    print(f"Current status: {service['Status']}")
    time.sleep(15)

print("Service is ready. Injecting MongoDB URI...")
source_config = service['SourceConfiguration']
source_config['ImageRepository']['ImageConfiguration']['RuntimeEnvironmentVariables']['MONGODB_URI'] = "mongodb+srv://anushree2k5_db_user:V33Ryxrh8VtUD83I@cluster0.utejvsm.mongodb.net"

with open('temp_source_config.json', 'w') as f:
    json.dump(source_config, f)

update_cmd = f"aws apprunner update-service --service-arn {arn} --region eu-central-1 --source-configuration file://temp_source_config.json"
try:
    subprocess.check_call(update_cmd, shell=True)
    print("✅ MongoDB URI injected! App Runner is redeploying with the cloud database.")
except Exception as e:
    print(f"❌ Failed to update App Runner: {e}")
