#!/usr/bin/env bash
set -euo pipefail

OWNER="c303s"
REPO="falcon-report"
BRANCH="main"
SCRIPT_NAME="falcon_report.py"

log() {
  printf "[install] %s\n" "$1"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf "[install] missing required command: %s\n" "$1" >&2
    exit 1
  fi
}

check_python() {
  python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required")
PY
}

resolve_sha() {
  local api_url="https://api.github.com/repos/${OWNER}/${REPO}/commits/${BRANCH}"
  curl -fsSL "$api_url" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])'
}

download_script() {
  local sha="$1"
  local raw_url="https://raw.githubusercontent.com/${OWNER}/${REPO}/${sha}/${SCRIPT_NAME}"
  curl -fsSL "$raw_url" -o "$SCRIPT_NAME"
}

main() {
  require_cmd curl
  require_cmd python3
  check_python

  log "resolving latest commit SHA from ${OWNER}/${REPO}@${BRANCH}"
  sha="$(resolve_sha)"
  log "resolved SHA: ${sha}"

  log "downloading ${SCRIPT_NAME} (SHA-pinned)"
  download_script "$sha"

  if [[ "${SKIP_RUN:-0}" == "1" ]]; then
    log "SKIP_RUN=1 set, not launching ${SCRIPT_NAME}"
    exit 0
  fi

  log "launching ${SCRIPT_NAME}"
  exec python3 "$SCRIPT_NAME"
}

main "$@"
