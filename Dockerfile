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

# Create non-root system user
RUN useradd -m -u 1000 appuser

# Copy installed python dependencies from builder to appuser
COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

# Copy application code
COPY backend/ ./backend/
COPY database/ ./database/
COPY data/ ./data/
COPY frontend/ ./frontend/
COPY run_standalone.py .

RUN chown -R appuser:appuser /app /home/appuser

# Environment settings for AWS production
ENV DEPLOYMENT_MODE="AWS_ECS_PROD"
ENV PORT=8000
ENV HOST="0.0.0.0"

USER appuser

EXPOSE 8000

# Healthcheck for AWS Load Balancer
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/system/status || exit 1

# Launch the FastAPI app via the standalone runner using Uvicorn (configured inside)
CMD ["python", "run_standalone.py"]
