import subprocess
import time
import json
import sys

arn = "arn:aws:apprunner:eu-central-1:242254325378:service/aws-security-app-service/e2c75827b7fe48a0963c9b0dc69ccc5e"

def get_status():
    try:
        res = subprocess.check_output(f"aws apprunner describe-service --service-arn {arn} --region eu-central-1", shell=True)
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
        subprocess.check_call(f"aws apprunner start-deployment --service-arn {arn} --region eu-central-1", shell=True)
        print("Favicon deployment triggered successfully!")
        break
    elif status in ["CREATE_FAILED", "UPDATE_FAILED", "DELETED"]:
        print(f"Terminal state reached: {status}")
        break
    time.sleep(30)
