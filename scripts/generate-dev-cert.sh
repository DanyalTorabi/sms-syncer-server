#!/usr/bin/env bash

set -euo pipefail

CERT_DIR="${1:-certs/dev}"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is required to generate local certificates"
  exit 1
fi

mkdir -p "${CERT_DIR}"

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "${KEY_FILE}"
chmod 644 "${CERT_FILE}"

echo "Local TLS certificate generated: ${CERT_FILE}"
echo "Local TLS private key generated: ${KEY_FILE}"
