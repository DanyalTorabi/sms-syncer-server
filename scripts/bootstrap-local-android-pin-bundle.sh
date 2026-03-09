#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs/dev"
CERT_FILE="${CERT_DIR}/server.crt"
BUNDLE_PATH="${ROOT_DIR}/docs/security/android-pin-bundle.json"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is required but not installed."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed."
  exit 1
fi

if [[ ! -f "${CERT_FILE}" ]]; then
  echo "Local cert not found. Generating dev certs in ${CERT_DIR}..."
  "${ROOT_DIR}/scripts/generate-dev-cert.sh" "${CERT_DIR}"
fi

if [[ ! -f "${BUNDLE_PATH}" ]]; then
  echo "Error: bundle file not found at ${BUNDLE_PATH}"
  exit 1
fi

if ! jq . "${BUNDLE_PATH}" >/dev/null 2>&1; then
  echo "Error: ${BUNDLE_PATH} is not valid JSON."
  exit 1
fi

to_iso_date() {
  local raw_date="$1"
  date -u -d "${raw_date}" +%F
}

current_pin="sha256/$(openssl x509 -in "${CERT_FILE}" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64)"

not_before_raw="$(openssl x509 -in "${CERT_FILE}" -noout -startdate | cut -d= -f2-)"
not_after_raw="$(openssl x509 -in "${CERT_FILE}" -noout -enddate | cut -d= -f2-)"
not_before="$(to_iso_date "${not_before_raw}")"
not_after="$(to_iso_date "${not_after_raw}")"
today="$(date +%F)"

tmp_file="$(mktemp)"

jq \
  --arg pin "${current_pin}" \
  --arg notBefore "${not_before}" \
  --arg notAfter "${not_after}" \
  --arg today "${today}" \
  '
  .lastUpdated = $today |
  .environments |= map(
    if .name == "development" then
      .androidPinningRequired = false |
      .notes = "Local HTTPS development bootstrap using certs/dev/server.crt" |
      .hosts = [
        {
          hostname: "localhost",
          edgeTlsTermination: "native",
          pins: {
            current: $pin,
            backup: $pin
          },
          validity: {
            notBefore: $notBefore,
            notAfter: $notAfter
          }
        }
      ]
    elif .name == "staging" or .name == "production" then
      .androidPinningRequired = false |
      .notes = "Temporary local-only bootstrap values. Replace with real environment host/pins before enabling pinning." |
      .hosts = [
        {
          hostname: "localhost",
          edgeTlsTermination: "native",
          pins: {
            current: $pin,
            backup: $pin
          },
          validity: {
            notBefore: $notBefore,
            notAfter: $notAfter
          }
        }
      ]
    else
      .
    end
  )
  ' "${BUNDLE_PATH}" >"${tmp_file}"

mv "${tmp_file}" "${BUNDLE_PATH}"

echo "Updated ${BUNDLE_PATH} for local development."
echo "Pin: ${current_pin}"
echo "Validity: ${not_before} -> ${not_after}"
echo "Review with: git --no-pager diff -- ${BUNDLE_PATH}"