FROM python:3.13.7-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN groupadd --system shadowtrace && useradd --system --gid shadowtrace --home-dir /app shadowtrace
COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt
COPY --chown=shadowtrace:shadowtrace . .
RUN mkdir -p /data && chown shadowtrace:shadowtrace /data

USER shadowtrace
ENV SHADOWTRACE_DATABASE=/data/shadowtrace.db SHADOWTRACE_THREAT_INTEL_MODE=offline
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=4", "--access-logfile=-", "dashboard.app:app"]
