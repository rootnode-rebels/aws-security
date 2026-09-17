# Production Multi-Stage Dockerfile for AWS ECS / ECR
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final production stage
FROM python:3.11-slim

WORKDIR /app
# Install curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy installed python dependencies from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY backend/ ./backend/
COPY database/ ./database/
COPY frontend/ ./frontend/
COPY run_standalone.py .

# Environment settings for AWS production
ENV DEPLOYMENT_MODE="AWS_ECS_PROD"
ENV PORT=80
ENV HOST="0.0.0.0"

EXPOSE 80

# Healthcheck for AWS Load Balancer
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:80/api/system/status || exit 1

# Launch the FastAPI app via the standalone runner using Uvicorn (configured inside)
CMD ["python", "run_standalone.py"]
