#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${ROOT_DIR}/docs/security/android-pin-bundle.json"
ARTIFACTS_DIR="${ROOT_DIR}/.artifacts/android-pin-inputs"

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed."
  echo "Install jq and rerun this script."
  exit 1
fi

if [[ ! -f "${BUNDLE_PATH}" ]]; then
  echo "Error: bundle file not found at ${BUNDLE_PATH}"
  exit 1
fi

if ! jq . "${BUNDLE_PATH}" >/dev/null 2>&1; then
  echo "Error: ${BUNDLE_PATH} is not valid JSON."
  exit 1
fi

require_non_empty() {
  local value="$1"
  local field_name="$2"
  if [[ -z "${value}" ]]; then
    echo "Error: ${field_name} cannot be empty."
    exit 1
  fi
}

validate_date() {
  local value="$1"
  local field_name="$2"
  if [[ ! "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "Error: ${field_name} must be in YYYY-MM-DD format." >&2
    return 1
  fi

  return 0
}

validate_pin() {
  local value="$1"
  local field_name="$2"
  if [[ "${value}" == *"REPLACE_WITH_"* ]]; then
    echo "Error: ${field_name} is still a placeholder. Enter a real SPKI pin." >&2
    return 1
  fi

  if [[ ! "${value}" =~ ^sha256/[A-Za-z0-9+/=]+$ ]]; then
    echo "Error: ${field_name} must look like sha256/<base64>." >&2
    return 1
  fi

  return 0
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

prompt_bool_default() {
  local prompt="$1"
  local default_value="$2"
  local response
  if ! read -r -p "${prompt} [${default_value}]: " response; then
    response=""
  fi
  if [[ -z "${response}" ]]; then
    response="${default_value}"
  fi
  response="$(echo "${response}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${response}" != "true" && "${response}" != "false" ]]; then
    echo "Error: enter true or false."
    exit 1
  fi
  printf '%s' "${response}"
}

prompt_env_host() {
  local env_name="$1"
  local default_host="$2"
  local default_termination="$3"
  local default_current_pin="$4"
  local default_backup_pin="$5"
  local default_not_before="$6"
  local default_not_after="$7"
  local out_prefix="$8"

  echo "" >&2
  echo "--- ${env_name} ---" >&2

  local hostname
  local edge_tls_termination
  local current_pin
  local backup_pin
  local not_before
  local not_after

  hostname="$(prompt_with_default "Hostname" "${default_host}")"
  require_non_empty "${hostname}" "${env_name} hostname"

  edge_tls_termination="$(prompt_with_default "Edge TLS termination (proxy|native|cdn)" "${default_termination}")"
  require_non_empty "${edge_tls_termination}" "${env_name} edgeTlsTermination"

  while true; do
    current_pin="$(prompt_with_default "Current SPKI pin" "${default_current_pin}")"
    if validate_pin "${current_pin}" "${env_name} current pin"; then
      break
    fi
  done

  while true; do
    backup_pin="$(prompt_with_default "Backup SPKI pin" "${default_backup_pin}")"
    if validate_pin "${backup_pin}" "${env_name} backup pin"; then
      break
    fi
  done

  while true; do
    not_before="$(prompt_with_default "Validity notBefore (YYYY-MM-DD)" "${default_not_before}")"
    if validate_date "${not_before}" "${env_name} validity.notBefore"; then
      break
    fi
  done

  while true; do
    not_after="$(prompt_with_default "Validity notAfter (YYYY-MM-DD)" "${default_not_after}")"
    if validate_date "${not_after}" "${env_name} validity.notAfter"; then
      break
    fi
  done

  printf -v "${out_prefix}hostname" '%s' "${hostname}"
  printf -v "${out_prefix}term" '%s' "${edge_tls_termination}"
  printf -v "${out_prefix}current" '%s' "${current_pin}"
  printf -v "${out_prefix}backup" '%s' "${backup_pin}"
  printf -v "${out_prefix}not_before" '%s' "${not_before}"
  printf -v "${out_prefix}not_after" '%s' "${not_after}"
}

echo "Updating ${BUNDLE_PATH}"
echo "Press Enter to keep defaults shown in brackets."

owner_default="$(jq -r '.owner' "${BUNDLE_PATH}")"
lead_time_default="$(jq -r '.changeManagement.rotationNoticeLeadTime' "${BUNDLE_PATH}")"

staging_host_default="$(jq -r '.environments[] | select(.name=="staging") | .hosts[0].hostname' "${BUNDLE_PATH}")"
staging_term_default="$(jq -r '.environments[] | select(.name=="staging") | .hosts[0].edgeTlsTermination' "${BUNDLE_PATH}")"
staging_curr_default="$(jq -r '.environments[] | select(.name=="staging") | .hosts[0].pins.current' "${BUNDLE_PATH}")"
staging_back_default="$(jq -r '.environments[] | select(.name=="staging") | .hosts[0].pins.backup' "${BUNDLE_PATH}")"
staging_nb_default="$(jq -r '.environments[] | select(.name=="staging") | .hosts[0].validity.notBefore' "${BUNDLE_PATH}")"
staging_na_default="$(jq -r '.environments[] | select(.name=="staging") | .hosts[0].validity.notAfter' "${BUNDLE_PATH}")"

prod_host_default="$(jq -r '.environments[] | select(.name=="production") | .hosts[0].hostname' "${BUNDLE_PATH}")"
prod_term_default="$(jq -r '.environments[] | select(.name=="production") | .hosts[0].edgeTlsTermination' "${BUNDLE_PATH}")"
prod_curr_default="$(jq -r '.environments[] | select(.name=="production") | .hosts[0].pins.current' "${BUNDLE_PATH}")"
prod_back_default="$(jq -r '.environments[] | select(.name=="production") | .hosts[0].pins.backup' "${BUNDLE_PATH}")"
prod_nb_default="$(jq -r '.environments[] | select(.name=="production") | .hosts[0].validity.notBefore' "${BUNDLE_PATH}")"
prod_na_default="$(jq -r '.environments[] | select(.name=="production") | .hosts[0].validity.notAfter' "${BUNDLE_PATH}")"

staging_artifact="${ARTIFACTS_DIR}/staging.json"
production_artifact="${ARTIFACTS_DIR}/production.json"

if [[ -f "${staging_artifact}" ]] && jq . "${staging_artifact}" >/dev/null 2>&1; then
  staging_host_default="$(jq -r '.hostname // empty' "${staging_artifact}")"
  staging_term_default="$(jq -r '.edgeTlsTermination // empty' "${staging_artifact}")"
  staging_curr_default="$(jq -r '.currentPin // empty' "${staging_artifact}")"
  staging_nb_default="$(jq -r '.validity.notBefore // empty' "${staging_artifact}")"
  staging_na_default="$(jq -r '.validity.notAfter // empty' "${staging_artifact}")"
  echo "Loaded staging defaults from ${staging_artifact}"
fi

if [[ -f "${production_artifact}" ]] && jq . "${production_artifact}" >/dev/null 2>&1; then
  prod_host_default="$(jq -r '.hostname // empty' "${production_artifact}")"
  prod_term_default="$(jq -r '.edgeTlsTermination // empty' "${production_artifact}")"
  prod_curr_default="$(jq -r '.currentPin // empty' "${production_artifact}")"
  prod_nb_default="$(jq -r '.validity.notBefore // empty' "${production_artifact}")"
  prod_na_default="$(jq -r '.validity.notAfter // empty' "${production_artifact}")"
  echo "Loaded production defaults from ${production_artifact}"
fi

owner="$(prompt_with_default "Owner" "${owner_default}")"
require_non_empty "${owner}" "owner"

lead_time="$(prompt_with_default "Rotation notice lead time" "${lead_time_default}")"
require_non_empty "${lead_time}" "rotationNoticeLeadTime"

staging_required_default="$(jq -r '.environments[] | select(.name=="staging") | .androidPinningRequired' "${BUNDLE_PATH}")"
production_required_default="$(jq -r '.environments[] | select(.name=="production") | .androidPinningRequired' "${BUNDLE_PATH}")"

staging_required="$(prompt_bool_default "Staging androidPinningRequired" "${staging_required_default}")"
production_required="$(prompt_bool_default "Production androidPinningRequired" "${production_required_default}")"

prompt_env_host "staging" "${staging_host_default}" "${staging_term_default}" "${staging_curr_default}" "${staging_back_default}" "${staging_nb_default}" "${staging_na_default}" "staging_"
prompt_env_host "production" "${prod_host_default}" "${prod_term_default}" "${prod_curr_default}" "${prod_back_default}" "${prod_nb_default}" "${prod_na_default}" "production_"

today="$(date +%F)"
tmp_file="$(mktemp)"

jq \
  --arg owner "${owner}" \
  --arg leadTime "${lead_time}" \
  --arg lastUpdated "${today}" \
  --arg stagingHost "${staging_hostname}" \
  --arg stagingTerm "${staging_term}" \
  --arg stagingCurrent "${staging_current}" \
  --arg stagingBackup "${staging_backup}" \
  --arg stagingNotBefore "${staging_not_before}" \
  --arg stagingNotAfter "${staging_not_after}" \
  --arg productionHost "${production_hostname}" \
  --arg productionTerm "${production_term}" \
  --arg productionCurrent "${production_current}" \
  --arg productionBackup "${production_backup}" \
  --arg productionNotBefore "${production_not_before}" \
  --arg productionNotAfter "${production_not_after}" \
  --argjson stagingRequired "${staging_required}" \
  --argjson productionRequired "${production_required}" \
  '
  .owner = $owner |
  .lastUpdated = $lastUpdated |
  .changeManagement.rotationNoticeLeadTime = $leadTime |
  .environments |= map(
    if .name == "staging" then
      .androidPinningRequired = $stagingRequired |
      .hosts[0].hostname = $stagingHost |
      .hosts[0].edgeTlsTermination = $stagingTerm |
      .hosts[0].pins.current = $stagingCurrent |
      .hosts[0].pins.backup = $stagingBackup |
      .hosts[0].validity.notBefore = $stagingNotBefore |
      .hosts[0].validity.notAfter = $stagingNotAfter
    elif .name == "production" then
      .androidPinningRequired = $productionRequired |
      .hosts[0].hostname = $productionHost |
      .hosts[0].edgeTlsTermination = $productionTerm |
      .hosts[0].pins.current = $productionCurrent |
      .hosts[0].pins.backup = $productionBackup |
      .hosts[0].validity.notBefore = $productionNotBefore |
      .hosts[0].validity.notAfter = $productionNotAfter
    else
      .
    end
  )
  ' "${BUNDLE_PATH}" >"${tmp_file}"

mv "${tmp_file}" "${BUNDLE_PATH}"

echo ""
echo "Updated ${BUNDLE_PATH} successfully."
echo "Tip: review the diff with: git --no-pager diff -- ${BUNDLE_PATH}"