"""
AWS Lambda Handler: Authentication & Session Management.
Processes API Gateway events for /auth/login, /auth/register, and /auth/sessions.
"""
import json
import os
import time

def lambda_handler(event, context):
    http_method = event.get("httpMethod", "GET")
    path = event.get("path", "")
    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except Exception:
            body = {}

    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,GET,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization"
    }

    if http_method == "OPTIONS":
        return {"statusCode": 200, "headers": headers, "body": ""}

    # Log to CloudWatch
    print(f"[CloudWatch /aws/lambda/AuthHandler] {http_method} {path} invoked with requestId: {context.aws_request_id if hasattr(context, 'aws_request_id') else 'local-req'}")

    # Production runtime guard (ISSUE-08)
    env_mode = os.getenv("DEPLOYMENT_MODE", "").upper()
    if env_mode in ("PRODUCTION", "AWS_ECS_PROD", "CLOUD") and os.getenv("ENABLE_LAMBDA_MOCK_AUTH", "false").lower() != "true":
        return {
            "statusCode": 503,
            "headers": headers,
            "body": json.dumps({
                "error": "Serverless Lambda mock authentication disabled in production. Routed to primary backend container API.",
                "status": "SERVICE_UNAVAILABLE"
            })
        }

    if path.endswith("/register") and http_method == "POST":
        if not body.get("email") or not body.get("password"):
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({"error": "Missing required registration parameters (email, password)."})
            }
        return {
            "statusCode": 201,
            "headers": headers,
            "body": json.dumps({"status": "success", "message": "User registered successfully."})
        }

    if path.endswith("/login") and http_method == "POST":
        email = body.get("email")
        password = body.get("password")
        if not email or not password:
            return {
                "statusCode": 400,
                "headers": headers,
                "body": json.dumps({"error": "Missing email or password credentials."})
            }
        # In mock evaluation mode, generate non-predictable session token
        import secrets
        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps({
                "status": "success",
                "message": "Authentication evaluated",
                "decision": {
                    "action": "ALLOW",
                    "risk_score": 12.5,
                    "session_token": f"aws_sec_tok_{secrets.token_urlsafe(24)}"
                }
            })
        }

    return {
        "statusCode": 404,
        "headers": headers,
        "body": json.dumps({"error": "Resource not found"})
    }
