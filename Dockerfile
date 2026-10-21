FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# krb5 client libs + kinit: host queries authenticate to workstations with Kerberos instead of NTLM.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    krb5-user \
    libkrb5-3 \
    libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/*
COPY docker/krb5.conf /etc/krb5.conf

COPY requirements.txt /app/requirements.txt
# pykerberos (WinRM Kerberos) is a C extension: build deps only for the pip step.
RUN apt-get update && apt-get install -y --no-install-recommends gcc libkrb5-dev \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apt-get purge -y gcc libkrb5-dev && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY app /app/app

RUN mkdir -p /app/data \
    && adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--log-level", "error"]
