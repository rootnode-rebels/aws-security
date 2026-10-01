$ErrorActionPreference = "Stop"

Write-Host "1. Committing to GitHub..."
git add .
git commit -m "fix(governance): add Maker-Checker dual control, safe PyMongo serialization, God Mode queue, and smooth theme transitions"
git push origin main

Write-Host "2. Building and Pushing to AWS ECR..."
aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin 242254325378.dkr.ecr.eu-central-1.amazonaws.com
docker build -t aws-security-app .
docker tag aws-security-app:latest 242254325378.dkr.ecr.eu-central-1.amazonaws.com/aws-security-app:latest
docker push 242254325378.dkr.ecr.eu-central-1.amazonaws.com/aws-security-app:latest

Write-Host "3. Triggering AWS App Runner Deployment..."
aws apprunner start-deployment --service-arn arn:aws:apprunner:eu-central-1:242254325378:service/aws-security-app-service/e2c75827b7fe48a0963c9b0dc69ccc5e --region eu-central-1

Write-Host "All deployments successfully triggered!"
