# ════════════════════════════════════════════════════════════════════════════
#  My Network Guard — Dockerfile
#  Multi-stage build: minimal attack surface, non-root runtime
#
#  Build:   docker build -f docker/Dockerfile -t my-network-guard:latest .
#  Run:     docker run -p 5000:5000 --env-file .env my-network-guard:latest
# ════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Dependency builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies (needed for wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ── Stage 2: Production runtime ───────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="My Network Guard Team" \
      version="2.0.0" \
      description="Network Intrusion Detection System"

# Runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create non-root app user (OWASP ASVS V14.1 — least privilege)
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/false appuser

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source
COPY --chown=appuser:appuser . .

# Ensure Python packages on PATH for appuser
ENV PATH="/home/appuser/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    PORT=5000 \
    HOST=0.0.0.0 \
    CONFIRM_OWNER=true \
    LOG_FORMAT=json

# Create persistent data directory
RUN mkdir -p /app/data && chown appuser:appuser /app/data

# NOTE: Live packet capture (Scapy/Npcap) requires privileged mode or
#       NET_RAW capability. In cloud deployments (Render), capture is
#       simulated. For local Docker capture:
#       docker run --cap-add=NET_RAW --cap-add=NET_ADMIN ...
# Expose port
EXPOSE 5000

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:5000/api/health').getcode() == 200 else 1)"

ENTRYPOINT ["python", "main.py"]
