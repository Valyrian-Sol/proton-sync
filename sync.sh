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

_verify_secure_python() {
    local bin_path="$1"
    if [[ "$bin_path" != /* ]]; then
        echo "FEHLER: Python-Pfad muss absolut sein: $bin_path" >&2
        return 1
    fi

    local resolved="$bin_path"
    if command -v readlink >/dev/null 2>&1; then
        resolved="$(readlink -f -- "$bin_path")" || return 1
    fi

    if [[ ! -f "$resolved" || ! -x "$resolved" ]]; then
        echo "FEHLER: Python-Binary nicht ausführbar oder keine reguläre Datei: $resolved" >&2
        return 1
    fi

    local uid perm
    read -r uid perm < <(stat -c '%u %a' -- "$resolved")
    if (( uid != 0 && uid != EUID )); then
        echo "FEHLER: Unsicherer Eigentümer (UID $uid) für Python-Binary: $resolved" >&2
        return 1
    fi
    if (( (8#$perm & 0002) != 0 )); then
        echo "FEHLER: Python-Binary ist world-writable: $resolved" >&2
        return 1
    fi

    local dir="${resolved%/*}"
    [[ -z "$dir" ]] && dir="/"
    while true; do
        read -r uid perm < <(stat -c '%u %a' -- "$dir")
        if (( uid != 0 && uid != EUID )); then
            echo "FEHLER: Unsicherer Eigentümer (UID $uid) für Verzeichnis: $dir" >&2
            return 1
        fi
        if (( (8#$perm & 0002) != 0 && (8#$perm & 01000) == 0 )); then
            echo "FEHLER: Verzeichnis ist world-writable ohne Sticky-Bit: $dir" >&2
            return 1
        fi
        [[ "$dir" == "/" ]] && break
        dir="${dir%/*}"
        [[ -z "$dir" ]] && dir="/"
    done

    RESOLVED_PYTHON="$resolved"
    return 0
}

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

if [[ -z "$PYTHON_BIN" ]]; then
    echo "FEHLER: Kein python3 unter /usr/bin oder /usr/local/bin gefunden (oder PROTON_SYNC_PYTHON setzen)." >&2
    exit 2
fi

RESOLVED_PYTHON=""
if ! _verify_secure_python "$PYTHON_BIN"; then
    exit 2
fi

# -I (Isolated Mode): ignoriert PYTHONPATH, PYTHONSTARTUP, ~/.local/lib site-packages und sys.path[0]
exec "$RESOLVED_PYTHON" -I "$SCRIPT_DIR/sync_proton_drive.py" "$@"
