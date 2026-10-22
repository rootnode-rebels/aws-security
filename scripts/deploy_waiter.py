import subprocess
import time
import json
import sys

import os

arn = os.getenv("APPRUNNER_SERVICE_ARN")
aws_region = os.getenv("AWS_REGION", "eu-central-1")

if not arn:
    print("[ERROR] APPRUNNER_SERVICE_ARN environment variable is required.")
    sys.exit(1)

def get_status():
    try:
        res = subprocess.check_output(["aws", "apprunner", "describe-service", "--service-arn", arn, "--region", aws_region])
        return json.loads(res.decode('utf-8'))['Service']['Status']
    except Exception as e:
        print(f"Error fetching status: {e}")
        return "ERROR"

print("Waiting for current deployment to finish before queuing the new favicon update...")
while True:
    status = get_status()
    print(f"Current status: {status}")
    if status == "RUNNING":
        print("Service is ready. Triggering the final favicon deployment!")
        subprocess.check_call(["aws", "apprunner", "start-deployment", "--service-arn", arn, "--region", aws_region])
        print("Favicon deployment triggered successfully!")
        break
    elif status in ["CREATE_FAILED", "UPDATE_FAILED", "DELETED"]:
        print(f"Terminal state reached: {status}")
        break
    time.sleep(30)
