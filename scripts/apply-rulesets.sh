#!/usr/bin/env bash

set -euo pipefail

MODE="preview"
REPO=""

for arg in "$@"; do
  case "$arg" in
    --apply)
      MODE="apply"
      ;;
    --repo=*)
      REPO="${arg#*=}"
      ;;
    *)
      echo "Unknown argument: $arg"
      echo "Usage: $0 [--apply] [--repo=<owner/repo>]"
      exit 1
      ;;
  esac
done

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required"
  exit 1
fi

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULESET_DIR="$ROOT_DIR/.github/rulesets"

if [[ ! -d "$RULESET_DIR" ]]; then
  echo "Ruleset directory not found: $RULESET_DIR"
  exit 1
fi

upsert_ruleset() {
  local file_path="$1"
  local ruleset_name
  ruleset_name="$(jq -r '.name' "$file_path")"

  if [[ -z "$ruleset_name" || "$ruleset_name" == "null" ]]; then
    echo "Invalid ruleset file (missing name): $file_path"
    exit 1
  fi

  local existing_id
  existing_id="$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$ruleset_name\") | .id" || true)"

  if [[ "$MODE" == "preview" ]]; then
    if [[ -n "$existing_id" ]]; then
      echo "[PREVIEW] Would update ruleset '$ruleset_name' (id: $existing_id) using $file_path"
    else
      echo "[PREVIEW] Would create ruleset '$ruleset_name' using $file_path"
    fi
    return 0
  fi

  if [[ -n "$existing_id" ]]; then
    gh api "repos/$REPO/rulesets/$existing_id" -X PUT --input "$file_path" >/dev/null
    echo "Updated ruleset '$ruleset_name' (id: $existing_id)"
  else
    gh api "repos/$REPO/rulesets" -X POST --input "$file_path" >/dev/null
    echo "Created ruleset '$ruleset_name'"
  fi
}

echo "Repository: $REPO"
echo "Mode: $MODE"

upsert_ruleset "$RULESET_DIR/main-and-develop.json"
upsert_ruleset "$RULESET_DIR/release.json"

if [[ "$MODE" == "apply" ]]; then
  echo "\nRuleset summary:"
  gh api "repos/$REPO/rulesets" --jq '.[] | {id, name, enforcement, target}'
fi
