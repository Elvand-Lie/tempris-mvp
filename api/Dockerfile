FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei scanner (latest stable)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# Download Nuclei community templates
RUN nuclei -update-templates -silent || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# H-01: Create non-root user for security
RUN useradd -m -r -s /bin/false tempris \
    && chown -R tempris:tempris /app

COPY --chown=tempris:tempris . .

# Ensure data/evidence and chroma directories exist and are writable
RUN mkdir -p /app/data/evidence /app/data/chroma && chown -R tempris:tempris /app/data

# L-04: Docker health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# H-01: Run as non-root user
USER tempris

EXPOSE 8000

CMD ["uvicorn", "index:app", "--host", "127.0.0.1", "--port", "8000"]
