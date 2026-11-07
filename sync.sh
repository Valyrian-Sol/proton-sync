#!/usr/bin/env bash
set -euo pipefail
unset CDPATH

SOURCE="${BASH_SOURCE[0]}"
if command -v readlink >/dev/null 2>&1; then
    RESOLVED_SOURCE="$(readlink -f -- "$SOURCE")"
else
    RESOLVED_SOURCE="$SOURCE"
fi

SCRIPT_DIR="$(cd -P -- "$(dirname -- "$RESOLVED_SOURCE")" >/dev/null 2>&1 && pwd)"

PYTHON_BIN="/usr/bin/python3"
if [[ ! -x "$PYTHON_BIN" ]]; then
    PYTHON_BIN="$(command -v python3)"
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/sync_proton_drive.py" "$@"
