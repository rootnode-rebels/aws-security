<#
.SYNOPSIS
    AWSSecurity AI - AWS ECR & Docker Deployment Script
.DESCRIPTION
    Builds the production Docker image, tags it, and pushes it to AWS ECR,
    optionally triggering an AWS App Runner service deployment.
.EXAMPLE
    .\deploy_hotfix.ps1
    .\deploy_hotfix.ps1 -AccountId 123456789012 -Region eu-central-1
    .\deploy_hotfix.ps1 -SkipDeploy
#>

param(
    [string]$AccountId = $env:AWS_ACCOUNT_ID,
    [string]$Region = $(if ($env:AWS_REGION) { $env:AWS_REGION } else { "eu-central-1" }),
    [string]$RepositoryName = $(if ($env:ECR_REPOSITORY_NAME) { $env:ECR_REPOSITORY_NAME } else { "aws-security-app" }),
    [string]$ImageTag = "latest",
    [string]$AppRunnerArn = $env:APPRUNNER_SERVICE_ARN,
    [switch]$SkipBuild,
    [switch]$SkipPush,
    [switch]$SkipDeploy
)

$ErrorActionPreference = "Stop"

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  AWSSecurity AI - AWS ECR & Docker Deployment Pipeline" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

# 1. Prerequisite verification
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Docker CLI is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] AWS CLI is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# 2. Determine AWS Account ID if not explicitly provided
if (-not $AccountId) {
    try {
        $callerId = aws sts get-caller-identity --query Account --output text 2>$null
        if ($callerId -and $callerId -match "^\d{12}$") {
            $AccountId = $callerId.Trim()
            Write-Host "[INFO] Detected AWS Account ID from STS: $AccountId" -ForegroundColor Green
        }
    } catch {
        # STS lookup skipped or credentials not configured
    }
}

if (-not $AccountId) {
    $AccountId = "123456789012"
    Write-Host "[WARN] No AWS_ACCOUNT_ID provided or detected. Defaulting to: $AccountId" -ForegroundColor Yellow
}

$EcrRegistry = "$AccountId.dkr.ecr.$Region.amazonaws.com"
$RemoteImageUri = "$EcrRegistry/$RepositoryName`:$ImageTag"

Write-Host "[CONFIG] Region:          $Region" -ForegroundColor Gray
Write-Host "[CONFIG] Account ID:      $AccountId" -ForegroundColor Gray
Write-Host "[CONFIG] Repository:      $RepositoryName" -ForegroundColor Gray
Write-Host "[CONFIG] Target Image:    $RemoteImageUri" -ForegroundColor Gray

# 3. AWS ECR Authentication & Docker Build
if (-not $SkipBuild) {
    Write-Host "`n[STEP 1/3] Building production Docker container..." -ForegroundColor Green
    docker build -t "$RepositoryName`:$ImageTag" .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Docker build failed with exit code $LASTEXITCODE." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "`n[STEP 1/3] Skipping Docker build (-SkipBuild specified)." -ForegroundColor Yellow
}

# 4. Push to AWS ECR
if (-not $SkipPush) {
    Write-Host "`n[STEP 2/3] Authenticating with AWS ECR & pushing image..." -ForegroundColor Green
    aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin $EcrRegistry
    docker tag "$RepositoryName`:$ImageTag" $RemoteImageUri
    docker push $RemoteImageUri
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Docker push to ECR failed." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "[SUCCESS] Image successfully pushed to $RemoteImageUri" -ForegroundColor Green
} else {
    Write-Host "`n[STEP 2/3] Skipping Docker push (-SkipPush specified)." -ForegroundColor Yellow
}

# 5. AWS App Runner Deployment
if (-not $SkipDeploy) {
    if ($AppRunnerArn) {
        Write-Host "`n[STEP 3/3] Triggering AWS App Runner deployment..." -ForegroundColor Green
        aws apprunner start-deployment --service-arn $AppRunnerArn --region $Region
        Write-Host "[SUCCESS] AWS App Runner deployment initiated for ARN: $AppRunnerArn" -ForegroundColor Green
    } else {
        Write-Host "`n[STEP 3/3] Skipping App Runner deployment (APPRUNNER_SERVICE_ARN not set). Use -AppRunnerArn to trigger." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n[STEP 3/3] Skipping App Runner deployment (-SkipDeploy specified)." -ForegroundColor Yellow
}

Write-Host "`n==============================================================" -ForegroundColor Cyan
Write-Host "  Pipeline execution finished successfully." -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

