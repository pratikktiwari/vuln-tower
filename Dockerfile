FROM python:3.11-slim

LABEL maintainer="Vuln Tower Contributors"
LABEL description="CVE monitoring and notification system - Vuln Tower (Vulnerability Tower)"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY vuln_tower/ ./vuln_tower/

# Create non-root user
RUN useradd -m -u 1000 vulntower && \
    chown -R vulntower:vulntower /app

USER vulntower

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "-m", "vuln_tower.main"]
