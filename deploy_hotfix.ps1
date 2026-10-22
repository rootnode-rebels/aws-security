$ErrorActionPreference = "Stop"

Write-Host "1. Committing to GitHub..."
git add .
git commit -m "fix(governance): add Maker-Checker dual control, safe PyMongo serialization, God Mode queue, and smooth theme transitions"
git push origin main

$AccountId = if ($env:AWS_ACCOUNT_ID) { $env:AWS_ACCOUNT_ID } else { "123456789012" }
$Region = if ($env:AWS_REGION) { $env:AWS_REGION } else { "eu-central-1" }
$AppRunnerArn = $env:APPRUNNER_SERVICE_ARN

Write-Host "2. Building and Pushing to AWS ECR..."
aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin "$AccountId.dkr.ecr.$Region.amazonaws.com"
docker build -t aws-security-app .
docker tag aws-security-app:latest "$AccountId.dkr.ecr.$Region.amazonaws.com/aws-security-app:latest"
docker push "$AccountId.dkr.ecr.$Region.amazonaws.com/aws-security-app:latest"

if ($AppRunnerArn) {
    Write-Host "3. Triggering AWS App Runner Deployment..."
    aws apprunner start-deployment --service-arn $AppRunnerArn --region $Region
} else {
    Write-Host "3. Skipping App Runner start-deployment (APPRUNNER_SERVICE_ARN not set in environment)."
}

Write-Host "All deployments successfully triggered!"
