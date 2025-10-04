# Dockerfile
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY powerdns_adguard_shim.py .

# Create non-root user
RUN useradd -m -u 1000 shim && chown -R shim:shim /app
USER shim

# Expose port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8081/healthz', timeout=2)"

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8081", "--workers", "4", "--access-logfile", "-", "--error-logfile", "-", "powerdns_adguard_shim:app"]