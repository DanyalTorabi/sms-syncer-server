#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/.artifacts/android-pin-inputs"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl is required but not installed."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed."
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

to_iso_date() {
  local raw_date="$1"
  date -u -d "${raw_date}" +%F
}

prompt_with_default() {
  local prompt="$1"
  local default_value="$2"
  local response
  if ! read -r -p "${prompt} [${default_value}]: " response; then
    response=""
  fi
  if [[ -z "${response}" ]]; then
    response="${default_value}"
  fi
  printf '%s' "${response}"
}

generate_for_env() {
  local env_name="$1"
  local default_host="$2"
  local default_termination="$3"

  local hostname
  local port
  local sni
  local termination
  local cert_file
  local current_pin
  local not_before_raw
  local not_after_raw
  local not_before
  local not_after
  local out_file

  echo ""
  echo "--- ${env_name} artifact generation ---"

  hostname="$(prompt_with_default "Public hostname" "${default_host}")"
  if [[ -z "${hostname}" ]]; then
    echo "Error: hostname cannot be empty for ${env_name}."
    exit 1
  fi

  port="$(prompt_with_default "Port" "443")"
  sni="$(prompt_with_default "SNI servername" "${hostname}")"
  termination="$(prompt_with_default "Edge TLS termination (proxy|native|cdn)" "${default_termination}")"

  cert_file="${OUTPUT_DIR}/${env_name}-leaf.pem"
  out_file="${OUTPUT_DIR}/${env_name}.json"

  echo "Fetching certificate from ${hostname}:${port} (SNI: ${sni})..."
  if ! openssl s_client -connect "${hostname}:${port}" -servername "${sni}" </dev/null 2>/dev/null | openssl x509 -out "${cert_file}"; then
    echo "Error: failed to fetch certificate for ${env_name}."
    exit 1
  fi

  current_pin="sha256/$(openssl x509 -in "${cert_file}" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl base64)"

  not_before_raw="$(openssl x509 -in "${cert_file}" -noout -startdate | cut -d= -f2-)"
  not_after_raw="$(openssl x509 -in "${cert_file}" -noout -enddate | cut -d= -f2-)"
  not_before="$(to_iso_date "${not_before_raw}")"
  not_after="$(to_iso_date "${not_after_raw}")"

  jq -n \
    --arg env "${env_name}" \
    --arg hostname "${hostname}" \
    --arg port "${port}" \
    --arg sni "${sni}" \
    --arg edgeTlsTermination "${termination}" \
    --arg currentPin "${current_pin}" \
    --arg notBefore "${not_before}" \
    --arg notAfter "${not_after}" \
    --arg generatedAt "$(date -u +%FT%TZ)" \
    '{
      env: $env,
      hostname: $hostname,
      port: $port,
      sni: $sni,
      edgeTlsTermination: $edgeTlsTermination,
      currentPin: $currentPin,
      validity: {
        notBefore: $notBefore,
        notAfter: $notAfter
      },
      generatedAt: $generatedAt
    }' >"${out_file}"

  echo "Saved ${env_name} artifact: ${out_file}"
  echo "Extracted current pin: ${current_pin}"
  echo "Validity: ${not_before} -> ${not_after}"
}

echo "Generating Android pin input artifacts into: ${OUTPUT_DIR}"
echo "These files are local-only and ignored by git."

generate_for_env "staging" "api-staging.example.com" "proxy"
generate_for_env "production" "api.example.com" "proxy"

echo ""
echo "Done. Next step: run make update-android-pin-bundle"
echo "The update script will use ${OUTPUT_DIR}/staging.json and ${OUTPUT_DIR}/production.json as defaults."