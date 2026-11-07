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

# Nur vertrauenswürdige Systempfade verwenden (kein $PATH-Lookup -> kein Hijacking
# über manipulierte Einträge wie ~/.local/bin). Abweichend per PROTON_SYNC_PYTHON setzbar.
PYTHON_BIN="${PROTON_SYNC_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
    for candidate in /usr/bin/python3 /usr/local/bin/python3; do
        if [[ -x "$candidate" ]]; then
            PYTHON_BIN="$candidate"
            break
        fi
    done
fi

if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
    echo "FEHLER: Kein python3 unter /usr/bin oder /usr/local/bin gefunden (oder PROTON_SYNC_PYTHON setzen)." >&2
    exit 2
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/sync_proton_drive.py" "$@"
