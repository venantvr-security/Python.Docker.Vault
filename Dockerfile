# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Validation de la clé publique au build via BuildKit sans l'inscrire dans les layers intermédiaires
RUN --mount=type=secret,id=build_pub_key,target=/var/secrets/client_id.pub \
    python -c "from cryptography.hazmat.primitives import serialization; \
    serialization.load_pem_public_key(open('/var/secrets/client_id.pub', 'rb').read())"

COPY vault.py client.py ./

RUN useradd -m -u 10001 appuser
USER appuser
