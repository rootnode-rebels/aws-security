import subprocess
import json
import time

def run(cmd):
    return subprocess.check_output(cmd, shell=True).decode('utf-8')

print('1. Creating IAM Role for App Runner...')
trust_policy = {
    'Version': '2012-10-17',
    'Statement': [{
        'Effect': 'Allow',
        'Principal': {'Service': 'build.apprunner.amazonaws.com'},
        'Action': 'sts:AssumeRole'
    }]
}
role_arn = None
try:
    policy_str = json.dumps(trust_policy)
    res = run(f"aws iam create-role --role-name AppRunnerECR --assume-role-policy-document '{policy_str}'")
    role_arn = json.loads(res)['Role']['Arn']
except Exception as e:
    print('Role might exist, fetching ARN...')
    res = run('aws iam get-role --role-name AppRunnerECR')
    role_arn = json.loads(res)['Role']['Arn']

print(f'Role ARN: {role_arn}')
print('2. Attaching ECR access policy...')
try:
    run('aws iam attach-role-policy --role-name AppRunnerECR --policy-arn arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess')
except:
    pass

print('Waiting 10 seconds for IAM propagation...')
time.sleep(10)

print('3. Deploying AWS App Runner Service...')
image_id = '242254325378.dkr.ecr.eu-north-1.amazonaws.com/aws-security-defense:latest'
source_config = {
    'ImageRepository': {
        'ImageIdentifier': image_id,
        'ImageConfiguration': {'Port': '8000'},
        'ImageRepositoryType': 'ECR'
    },
    'AuthenticationConfiguration': {
        'AccessRoleArn': role_arn
    }
}
cmd = f"aws apprunner create-service --service-name aws-security-defense --source-configuration '{json.dumps(source_config)}'"
try:
    res = run(cmd)
    data = json.loads(res)
    url = data['Service']['ServiceUrl']
    print(f'✅ App Runner Deployment Initiated!')
    print(f'🌐 Live URL: https://{url}')
except Exception as e:
    print('Deployment Failed:', str(e))
