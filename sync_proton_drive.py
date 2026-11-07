#!/usr/bin/env python3
"""
Proton Drive Sync-Script (Einweg-Synchronisation PC -> Proton Drive)

Synchronisiert:
1. Alle Unterordner in ~/Dokumente -> /my-files/<Unterordner>
   (lose Dateien direkt in ~/Dokumente werden ignoriert!)
2. Den Ordner ~/Zotero -> /my-files/Zotero

Regeln & Sicherheitsgarantien:
- Bestimmte Ordner UND Einzeldateien können über `DEFAULT_EXCLUDED_FOLDERS`,
  `exclude.txt` (`exclude.local.txt`, `~/.config/proton-sync/exclude.txt`) oder
  `--exclude` / `-x` von der Synchronisation ausgeschlossen werden. Der Abgleich
  ignoriert Groß-/Kleinschreibung und Unicode-Normalisierungsformen (NFC/NFD).
- Explizit per `--exclude-file` angegebene oder fehlerhafte Ausschlussdateien
  arbeiten strikt nach dem Fail-Closed-Prinzip (Abbruch statt ungeschütztem Upload).
- Versteckte Dateien/Ordner (`.env`, `.git`, ...), Symlinks, Hardlinks, Spezialdateien
  und fremde Dateisysteme (Mount-Points) werden niemals ungeprüft hochgeladen.
- `proton-drive` erhält niemals die echten Quellordner zum rekursiven Durchlaufen,
  sondern einen privaten Staging-Bereich aus Hardlinks, die per Inode gegen den
  Scan abgeglichen werden (Schutz gegen nachträglich eingeschleuste Dateien/Symlinks).
- Neue Dateien und Ordner werden hochgeladen.
- Dateien, die in der Cloud älter sind als auf dem PC, werden durch die
  PC-Version ersetzt (als neue Revision über `-f create-new-revision -d merge`).
- Dateien, die in der Cloud neuer oder gleich alt (bzw. inhaltsgleich) sind,
  werden nicht überschrieben; verdächtige Zukunfts-Zeitstempel in Cloud-Metadaten
  werden erkannt und gemeldet.
- Es werden NIEMALS Dateien oder Ordner gelöscht (keine Löschbefehle, Ordner-Strategie
  `merge`). Die Strategie `replace` (verschiebt Cloud-Dateien in den Papierkorb) ist nur
  mit dem ausdrücklichen Flag `--allow-trash` verfügbar.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple


def _default_documents_dir() -> Path:
    dok = Path.home() / "Dokumente"
    docs = Path.home() / "Documents"
    if not dok.exists() and docs.exists():
        return docs
    return dok


SYSTEM_PROTON_BIN_CANDIDATES: Tuple[str, ...] = (
    "/usr/bin/proton-drive",
    "/usr/local/bin/proton-drive",
)


def _default_proton_drive_bin() -> str:
    """
    Nutzt ausschließlich vertrauenswürdige Systempfade (kein `$PATH`-Lookup, damit
    manipulierte Einträge wie `~/.local/bin` kein fremdes Binary unterschieben können).
    Andere Installationsorte müssen explizit per `--proton-bin` angegeben werden.
    """
    for candidate in SYSTEM_PROTON_BIN_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return SYSTEM_PROTON_BIN_CANDIDATES[0]


PROTON_DRIVE_BIN = _default_proton_drive_bin()
REMOTE_ROOT = "/my-files"
DEFAULT_DOKUMENTE = _default_documents_dir()
DEFAULT_ZOTERO = Path.home() / "Zotero"
DEFAULT_EXCLUDE_FILE = Path(__file__).resolve().parent / "exclude.txt"
DEFAULT_LOCAL_EXCLUDE_FILE = Path(__file__).resolve().parent / "exclude.local.txt"
DEFAULT_USER_EXCLUDE_FILE = Path.home() / ".config" / "proton-sync" / "exclude.txt"

STAGING_PREFIX = ".proton-sync-stage-"
MAX_WORKERS_LIMIT = 16
DEFAULT_LIST_TIMEOUT_SEC = 60
FUTURE_MTIME_SKEW_TOLERANCE = datetime.timedelta(minutes=5)

ZOTERO_SQLITE_SIDE_FILES = frozenset(
    {
        "zotero.sqlite",
        "zotero.sqlite-wal",
        "zotero.sqlite-shm",
        "zotero.sqlite-journal",
        "zotero.sqlite.lock",
    }
)
ZOTERO_SQLITE_MARKERS = (
    "zotero.sqlite.lock",
    "zotero.sqlite-journal",
    "zotero.sqlite-wal",
    "zotero.sqlite-shm",
)

BIDI_CONTROL_CHARS = frozenset(
    {
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)

# Feste Ausschlussliste im Skript (Ordner-/Dateinamen, relative Pfade wie "Projekte/Archiv",
# Glob-Muster wie "node_modules", "*.kdbx" oder absolute Pfade wie "~/Dokumente/Videos"):
DEFAULT_EXCLUDED_FOLDERS: List[str] = [
    # Beispiele:
    # "Videos",
    # "node_modules",
    # "__pycache__",
]


class ToctouError(Exception):
    """Ein lokales Element hat sich zwischen Scan und Upload verändert (z. B. Symlink-Tausch)."""


# --------------------------------------------------------------------------------------
# Hilfsfunktionen: Ausgabe, Namen, Binary-Prüfung
# --------------------------------------------------------------------------------------


def safe_str(value: object) -> str:
    """
    Maskiert Steuerzeichen (ANSI-Escapes, CR/LF, NUL) und Unicode-BiDi-Overrides,
    damit manipulierte Dateinamen niemals Terminal-Ausgaben (z. B. im --dry-run)
    überschreiben oder verschleiern können.
    """
    text = str(value)
    out: List[str] = []
    for ch in text:
        code = ord(ch)
        if (
            code < 0x20
            or code == 0x7F
            or (0x80 <= code <= 0x9F)
            or ch in BIDI_CONTROL_CHARS
        ):
            if code <= 0xFF:
                out.append(f"\\x{code:02x}")
            else:
                out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def normalize_for_match(value: str) -> str:
    """Normalisiert für Ausschluss-Vergleiche: Unicode-NFC + Groß-/Kleinschreibung ignorieren."""
    return unicodedata.normalize("NFC", value).casefold()


def is_valid_hex_digest(value: object, expected_len: int) -> bool:
    if not isinstance(value, str) or len(value) != expected_len:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def is_safe_node_name(name: str) -> Tuple[bool, str]:
    """Prüft einen einzelnen Pfadknotennamen auf Traversierungs- und Maskierungsrisiken."""
    if not name:
        return False, "Leerer Knotenname ist nicht erlaubt"
    if name in (".", ".."):
        return False, f"Reservierter Pfadname '{name}' ist nicht erlaubt"
    if "\x00" in name:
        return False, "NUL-Byte im Knotennamen ist nicht erlaubt"
    if "\\" in name:
        return (
            False,
            "Backslash '\\' im Namen ist mehrdeutig (Escape-Zeichen in proton-drive-Pfaden)",
        )
    return True, ""


def validate_proton_binary(path_str: str) -> Tuple[bool, Optional[str], str]:
    """
    Prüft, ob das `proton-drive` Binary existiert, ausführbar ist, einem
    vertrauenswürdigen Benutzer (root oder aktuellem User) gehört und weder
    selbst noch im Elternordner ungeschützt world-writable ist.
    """
    if not path_str:
        return False, None, "Kein Pfad für proton-drive angegeben"

    expanded = os.path.expanduser(path_str)
    resolved = os.path.realpath(expanded)
    try:
        st = os.stat(resolved)
    except OSError as exc:
        return (
            False,
            None,
            f"proton-drive CLI nicht gefunden unter '{safe_str(path_str)}': {safe_str(exc)} "
            "(andere Installationsorte bitte explizit per --proton-bin angeben)",
        )

    if not stat.S_ISREG(st.st_mode) or not os.access(resolved, os.X_OK):
        return (
            False,
            None,
            f"proton-drive Pfad ist keine ausführbare Datei: {safe_str(resolved)}",
        )

    allowed_uids = {0, os.geteuid()}
    if st.st_uid not in allowed_uids:
        return (
            False,
            None,
            f"Unsicherer Eigentümer (UID {st.st_uid}) für Binary: {safe_str(resolved)}",
        )

    if st.st_mode & stat.S_IWOTH:
        return (
            False,
            None,
            f"Unsichere Dateirechte (world-writable) für Binary: {safe_str(resolved)}",
        )

    parent_dir = os.path.dirname(resolved) or "/"
    try:
        parent_st = os.stat(parent_dir)
    except OSError as exc:
        return (
            False,
            None,
            f"Elternverzeichnis von proton-drive nicht prüfbar: {safe_str(exc)}",
        )

    if (parent_st.st_mode & stat.S_IWOTH) and not (parent_st.st_mode & stat.S_ISVTX):
        return (
            False,
            None,
            f"Elternverzeichnis des Binarys ist world-writable ohne Sticky-Bit: {safe_str(parent_dir)}",
        )

    if parent_st.st_uid not in allowed_uids:
        return (
            False,
            None,
            f"Unsicherer Eigentümer (UID {parent_st.st_uid}) für Binary-Verzeichnis: {safe_str(parent_dir)}",
        )

    return True, resolved, ""


class SingleInstanceLock:
    """Verhindert parallele Sync-Läufe über ein exklusives Dateisperr-Lock (flock)."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.fd: Optional[int] = None
        self.lock_path: Optional[Path] = None

    @staticmethod
    def _select_lock_dir() -> Path:
        uid = os.geteuid()
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", "").strip()
        if xdg_runtime and os.path.isabs(xdg_runtime):
            try:
                st = os.lstat(xdg_runtime)
                if (
                    stat.S_ISDIR(st.st_mode)
                    and st.st_uid == uid
                    and (st.st_mode & 0o077) == 0
                ):
                    return Path(xdg_runtime)
            except OSError:
                pass

        fallback = Path.home() / ".cache" / "proton-sync"
        fallback.mkdir(parents=True, mode=0o700, exist_ok=True)
        st = os.lstat(fallback)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
            raise PermissionError(
                f"Unsicheres Lock-Verzeichnis: {safe_str(fallback)}"
            )
        if st.st_mode & 0o077:
            os.chmod(fallback, 0o700)
        return fallback

    def __enter__(self) -> "SingleInstanceLock":
        if not self.enabled:
            return self
        lock_dir = self._select_lock_dir()
        self.lock_path = lock_dir / "proton-sync.lock"
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        self.fd = os.open(str(self.lock_path), flags, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError(
                f"Es läuft bereits eine andere Instanz von proton-sync (Lock aktiv: {safe_str(self.lock_path)})."
            ) from exc
        os.ftruncate(self.fd, 0)
        os.write(self.fd, f"{os.getpid()}\n".encode("ascii"))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


# --------------------------------------------------------------------------------------
# Datenstrukturen
# --------------------------------------------------------------------------------------


@dataclass
class RemoteNode:
    name: str
    node_type: str  # "file" | "folder"
    modification_time: Optional[datetime.datetime] = None
    claimed_mtime: Optional[datetime.datetime] = None
    claimed_size: Optional[int] = None
    claimed_sha1: Optional[str] = None
    claimed_sha256: Optional[str] = None

    @property
    def effective_mtime(self) -> Optional[datetime.datetime]:
        """Bevorzugt die ursprüngliche Datei-Änderungszeit (claimedModificationTime)."""
        return self.claimed_mtime or self.modification_time


@dataclass
class TreeMember:
    """Ein geprüftes Element innerhalb eines neuen Ordners (relativer POSIX-Pfad)."""

    rel: str
    is_dir: bool
    dev: int = 0
    ino: int = 0


@dataclass
class SyncAction:
    local_path: Path
    remote_parent: str
    reason: str  # "new_tree", "new_file", "updated_file"
    details: str = ""
    remote_name: Optional[str] = None
    dev: int = 0
    ino: int = 0
    members: List[TreeMember] = field(default_factory=list)

    @property
    def target_name(self) -> str:
        return self.remote_name or self.local_path.name


@dataclass
class ScanPolicy:
    """Gemeinsame Filterregeln für Scan, Planung und Ausführung."""

    include_hidden: bool = False
    exclude_patterns: Sequence[str] = ()
    base_dirs: Sequence[Path] = ()
    locked_skip_files: FrozenSet[Path] = frozenset()
    allow_hardlinks: bool = False
    allowed_devs: FrozenSet[int] = frozenset()  # leer = keine Dateisystem-Beschränkung


@dataclass
class SyncStats:
    folders_checked: int = 0
    new_folders: int = 0
    new_files: int = 0
    updated_files: int = 0
    skipped_identical: int = 0
    skipped_remote_newer_or_equal: int = 0
    skipped_symlinks: int = 0
    skipped_special: int = 0
    ignored_loose_files: List[Path] = field(default_factory=list)
    excluded_folders: List[Tuple[Path, str]] = field(default_factory=list)
    excluded_files: List[Tuple[Path, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# Zeitstempel, Remote-Pfade, Hashes
# --------------------------------------------------------------------------------------


def parse_iso_timestamp(value: Optional[str]) -> Optional[datetime.datetime]:
    """Parst einen ISO-8601-Zeitstempel (z. B. '2026-02-04T22:23:39.807Z') nach UTC."""
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except ValueError:
        return None


def escape_remote_segment(name: str) -> str:
    """Maskiert Schrägstriche im Knotennamen gemäß proton-drive CLI-Konvention."""
    ok, reason = is_safe_node_name(name)
    if not ok:
        raise ValueError(f"Unsicherer Remote-Knotenname '{safe_str(name)}': {reason}")
    return name.replace("/", r"\/")


def join_remote_path(parent: str, name: str) -> str:
    if parent != "/" and parent.endswith("/") and not parent.endswith(r"\/"):
        parent_clean = parent[:-1]
    else:
        parent_clean = parent

    if not (
        parent_clean == REMOTE_ROOT or parent_clean.startswith(REMOTE_ROOT + "/")
    ):
        raise ValueError(
            f"Remote-Ziel außerhalb von {REMOTE_ROOT} verweigert: {safe_str(parent)}"
        )

    escaped = escape_remote_segment(name)
    return f"{parent_clean}/{escaped}"


def compute_digests(file_path: Path, need_sha256: bool = False) -> Tuple[str, Optional[str]]:
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256() if need_sha256 else None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(file_path), flags)
    with os.fdopen(fd, "rb") as f:
        while chunk := f.read(1024 * 1024):
            sha1.update(chunk)
            if sha256 is not None:
                sha256.update(chunk)
    return sha1.hexdigest().lower(), (sha256.hexdigest().lower() if sha256 else None)


def compute_sha1(file_path: Path) -> str:
    digest, _ = compute_digests(file_path, need_sha256=False)
    return digest


def get_local_mtime_utc(file_path: Path) -> datetime.datetime:
    st = file_path.stat()
    return datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)


# --------------------------------------------------------------------------------------
# Ausschlussmuster
# --------------------------------------------------------------------------------------


def _split_cli_exclude(raw: str) -> List[str]:
    """Teilt kommagetrennte Muster, erlaubt aber '\\,' für Namen mit Komma."""
    parts: List[str] = []
    buf: List[str] = []
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw) and raw[i + 1] == ",":
            buf.append(",")
            i += 2
        elif raw[i] == ",":
            parts.append("".join(buf))
            buf = []
            i += 1
        else:
            buf.append(raw[i])
            i += 1
    parts.append("".join(buf))
    return parts


def _read_exclude_file_strict(file_path: Path, required: bool) -> List[str]:
    """
    Liest eine Ausschlussdatei nach dem Fail-Closed-Prinzip:
    - Fehlt eine optionale Standarddatei komplett, wird `[]` zurückgegeben.
    - Fehlt eine explizit angeforderte Datei (`required=True`) oder ist eine vorhandene
      Datei ein Verzeichnis, ein defekter Symlink oder nicht lesbar, wird ein Fehler ausgelöst.
    """
    expanded = file_path.expanduser()
    exists = expanded.exists()
    is_link = expanded.is_symlink()

    if not exists and not is_link:
        if required:
            raise FileNotFoundError(
                f"Angegebene Ausschlussdatei existiert nicht: {safe_str(expanded)}"
            )
        return []

    if is_link and not exists:
        raise FileNotFoundError(
            f"Ausschlussdatei ist ein defekter Symlink: {safe_str(expanded)}"
        )

    if not expanded.is_file():
        raise IsADirectoryError(
            f"Ausschlussdatei ist keine reguläre Datei: {safe_str(expanded)}"
        )

    lines: List[str] = []
    content = expanded.read_text(encoding="utf-8")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_exclude_patterns(
    cli_excludes: Optional[Sequence[str]] = None,
    exclude_file: Optional[Path] = DEFAULT_EXCLUDE_FILE,
    default_excludes: Optional[Sequence[str]] = None,
    *,
    require_exclude_file: bool = False,
    extra_exclude_files: Sequence[Path] = (),
) -> List[str]:
    """
    Lädt und kombiniert alle Ordner-/Datei-Ausschlussmuster aus:
    1. `default_excludes` (bzw. `DEFAULT_EXCLUDED_FOLDERS`)
    2. `extra_exclude_files` (optional, z. B. `~/.config/proton-sync/exclude.txt`, `exclude.local.txt`)
    3. `exclude_file` (standardmäßig `exclude.txt` im Skript-Ordner; bei `--exclude-file` Pflicht!)
    4. `cli_excludes` (`--exclude` / `-x` Parameter, auch kommagetrennt; `\\,` für literales Komma)
    """
    patterns: List[str] = []

    base_list = (
        list(default_excludes)
        if default_excludes is not None
        else list(DEFAULT_EXCLUDED_FOLDERS)
    )
    for item in base_list:
        cleaned = item.strip()
        if cleaned and cleaned not in patterns:
            patterns.append(cleaned)

    for extra_file in extra_exclude_files:
        for line in _read_exclude_file_strict(extra_file, required=False):
            if line not in patterns:
                patterns.append(line)

    if exclude_file is not None:
        for line in _read_exclude_file_strict(
            exclude_file, required=require_exclude_file
        ):
            if line not in patterns:
                patterns.append(line)

    if cli_excludes:
        for raw in cli_excludes:
            for part in _split_cli_exclude(raw):
                cleaned = part.strip()
                if cleaned and cleaned not in patterns:
                    patterns.append(cleaned)

    return patterns


def is_excluded_path(
    target_path: Path,
    exclude_patterns: Sequence[str],
    base_dirs: Sequence[Path] = (),
) -> Tuple[bool, Optional[str]]:
    """
    Prüft, ob ein Ordner oder eine Datei `target_path` durch eines der Muster in
    `exclude_patterns` ausgeschlossen ist. Der Vergleich ignoriert Groß-/Kleinschreibung
    und Unicode-Normalisierungsformen (`*.kdbx` trifft auch `Tresor.KDBX`).

    Unterstützte Musterformate:
    - Einfacher Ordner-/Dateiname oder Glob-Muster (ohne '/'), z. B.:
      `"Videos"`, `"node_modules"`, `"*.kdbx"`, `"*backup*"`
    - Relativer Pfad ab `~/Dokumente` oder `~/Zotero` (bzw. `base_dirs`), auch wenn
      der Basisordner ein Symlink ist, z. B.:
      `"Projekte/Archiv"`, `"Zotero/locate"`, `"Projekte/*.key"`
    - Absoluter Pfad oder `~`-Pfad (logisch & aufgelöst), z. B.:
      `"~/Dokumente/Videos"`, `"/home/<user>/Dokumente/Videos"`

    Gibt `(True, passendes_muster)` oder `(False, None)` zurück.
    """
    if not exclude_patterns:
        return False, None

    norm = normalize_for_match
    expanded_target_str = os.path.expanduser(str(target_path))
    logical_target = Path(os.path.abspath(expanded_target_str))
    resolved_target = target_path.expanduser().resolve()
    target_name = norm(target_path.name or resolved_target.name)

    rel_candidates: List[str] = []
    for base in base_dirs:
        expanded_base_str = os.path.expanduser(str(base))
        logical_base = Path(os.path.abspath(expanded_base_str))
        resolved_base = base.expanduser().resolve()
        base_names = [
            b.name
            for b in (logical_base, resolved_base)
            if b.name and b.name not in (".", "..")
        ]

        for tgt, bs in ((logical_target, logical_base), (resolved_target, resolved_base)):
            try:
                rel = tgt.relative_to(bs).as_posix()
            except ValueError:
                continue
            candidates = (
                [rel] + [f"{bname}/{rel}" for bname in base_names]
                if rel != "."
                else list(base_names)
            )
            for cand in candidates:
                cand_norm = norm(cand)
                if cand_norm not in rel_candidates:
                    rel_candidates.append(cand_norm)

    target_posix_variants = {norm(logical_target.as_posix()), norm(resolved_target.as_posix())}

    for raw_pattern in exclude_patterns:
        stripped = raw_pattern.strip().rstrip("/")
        if not stripped:
            continue

        # 1. Absoluter Pfad oder ~/... Pfad (prüft sowohl logischen als auch aufgelösten Pfad)
        if stripped.startswith("/") or stripped.startswith("~"):
            pat_variants = {
                norm(Path(os.path.abspath(os.path.expanduser(stripped))).as_posix().rstrip("/")),
                norm(Path(stripped).expanduser().resolve().as_posix().rstrip("/")),
            }
            for folder_posix in target_posix_variants:
                for pat_posix in pat_variants:
                    if not pat_posix:
                        continue
                    if (
                        folder_posix == pat_posix
                        or folder_posix.startswith(pat_posix + "/")
                        or fnmatch.fnmatchcase(folder_posix, pat_posix)
                    ):
                        return True, raw_pattern
            continue

        pattern = norm(stripped)

        # 2. Muster ohne '/' -> prüft den Datei-/Ordnernamen direkt (auf jeder Ebene)
        if "/" not in pattern:
            if fnmatch.fnmatchcase(target_name, pattern):
                return True, raw_pattern

        # 3. Muster mit '/' -> prüft relative Pfade ab den Basisverzeichnissen
        for rel in rel_candidates:
            if (
                rel == pattern
                or rel.startswith(pattern + "/")
                or fnmatch.fnmatchcase(rel, pattern)
            ):
                return True, raw_pattern

    return False, None


def is_excluded_folder(
    folder_path: Path,
    exclude_patterns: Sequence[str],
    base_dirs: Sequence[Path] = (),
) -> Tuple[bool, Optional[str]]:
    """Rückwärtskompatibler Alias für `is_excluded_path`."""
    return is_excluded_path(folder_path, exclude_patterns, base_dirs)


# --------------------------------------------------------------------------------------
# Zotero-Datenbankschutz
# --------------------------------------------------------------------------------------


def _zotero_process_running() -> bool:
    """
    Prüft minimal-invasiv, ob ein Zotero-Prozess läuft: Es wird ausschließlich
    `/proc/<pid>/comm` (Prozessname) gelesen – keine Dateideskriptoren fremder Prozesse.
    """
    proc_root = "/proc"
    if not os.path.isdir(proc_root):
        return False
    my_pid = os.getpid()
    try:
        entries = list(os.scandir(proc_root))
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isdigit() or int(entry.name) == my_pid:
            continue
        try:
            with open(os.path.join(entry.path, "comm"), "r", encoding="utf-8", errors="replace") as f:
                comm = f.read().strip().lower()
        except OSError:
            continue
        if "zotero" in comm:
            return True
    return False


def zotero_db_state(zotero_dir: Path) -> Optional[str]:
    """
    Gibt `None` zurück, wenn `zotero.sqlite` gefahrlos kopiert werden kann, andernfalls
    eine Begründung (Zotero läuft bzw. verwaiste Journal-/WAL-/Lock-Dateien).
    """
    if not (zotero_dir / "zotero.sqlite").exists():
        return None
    if _zotero_process_running():
        return "Zotero läuft gerade"
    leftovers = [m for m in ZOTERO_SQLITE_MARKERS if os.path.lexists(zotero_dir / m)]
    if leftovers:
        return (
            "verwaiste Datenbank-Hilfsdateien gefunden ("
            + ", ".join(leftovers)
            + ") – Zotero einmal starten und regulär beenden"
        )
    return None


def is_zotero_sqlite_in_use(zotero_dir: Path) -> bool:
    """Rückwärtskompatibler Wrapper: `True`, wenn `zotero.sqlite` nicht konsistent kopierbar ist."""
    return zotero_db_state(zotero_dir) is not None


# --------------------------------------------------------------------------------------
# Scan & Planung
# --------------------------------------------------------------------------------------


def classify_entry(
    child: Path,
    policy: ScanPolicy,
    stats: SyncStats,
) -> Optional[Tuple[str, os.stat_result]]:
    """
    Zentrale Filterentscheidung für jedes lokale Element.
    Gibt `("dir"|"file", lstat_result)` zurück oder `None`, wenn das Element nicht
    synchronisiert werden darf (Grund wird in `stats` vermerkt).
    """
    name = child.name
    if name.startswith(STAGING_PREFIX):
        return None
    if name.startswith(".") and not policy.include_hidden:
        return None

    try:
        st = os.lstat(child)
    except OSError as exc:
        stats.errors.append(
            f"Konnte Element nicht prüfen {safe_str(child)}: {safe_str(exc)}"
        )
        return None

    if stat.S_ISLNK(st.st_mode):
        stats.skipped_symlinks += 1
        return None

    ok_name, name_reason = is_safe_node_name(name)
    if not ok_name:
        stats.errors.append(
            f"Überspringe Element mit unsicherem Namen {safe_str(child)}: {name_reason}"
        )
        return None

    if policy.allowed_devs and st.st_dev not in policy.allowed_devs:
        stats.warnings.append(
            f"Anderes Dateisystem / Mount-Point übersprungen: {safe_str(child)} "
            "(--cross-filesystems zum Einbeziehen)"
        )
        return None

    if stat.S_ISDIR(st.st_mode):
        excluded, matched = is_excluded_path(child, policy.exclude_patterns, policy.base_dirs)
        if excluded:
            stats.excluded_folders.append((child, matched or ""))
            return None
        return "dir", st

    if stat.S_ISREG(st.st_mode):
        excluded, matched = is_excluded_path(child, policy.exclude_patterns, policy.base_dirs)
        if excluded:
            stats.excluded_files.append((child, matched or ""))
            return None
        if policy.locked_skip_files and child.resolve() in policy.locked_skip_files:
            return None
        if st.st_nlink > 1 and not policy.allow_hardlinks:
            stats.warnings.append(
                f"Hardlink übersprungen (Linkanzahl {st.st_nlink}): {safe_str(child)} – "
                "könnte auf Dateien außerhalb der Quellordner zeigen (--allow-hardlinks zum Einbeziehen)"
            )
            return None
        return "file", st

    stats.skipped_special += 1
    return None


def plan_new_folder_with_exclusions(
    local_dir: Path,
    remote_parent: str,
    policy: ScanPolicy,
    stats: SyncStats,
    _visited_inodes: Optional[Set[Tuple[int, int]]] = None,
    remote_name: Optional[str] = None,
) -> List[SyncAction]:
    """
    Plant den Upload eines in der Cloud noch nicht existierenden Ordners `local_dir`.
    Der gesamte Teilbaum wird in Python mit `classify_entry` gefiltert; das Ergebnis ist
    genau eine `new_tree`-Aktion mit einer expliziten Liste geprüfter Mitglieder
    (inkl. Inode-Nummern für den späteren TOCTOU-Abgleich).
    """
    effective_name = remote_name if remote_name is not None else local_dir.name
    ok_name, reason = is_safe_node_name(effective_name)
    if not ok_name:
        stats.errors.append(
            f"Überspringe Ordner mit unsicherem Namen {safe_str(local_dir)}: {reason}"
        )
        return []

    try:
        join_remote_path(remote_parent, effective_name)
    except ValueError as exc:
        stats.errors.append(str(exc))
        return []

    visited = _visited_inodes if _visited_inodes is not None else set()
    try:
        root_st = os.lstat(local_dir)
    except OSError as exc:
        stats.errors.append(
            f"Konnte lokalen Ordner nicht prüfen {safe_str(local_dir)}: {safe_str(exc)}"
        )
        return []
    if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
        return []
    root_key = (root_st.st_dev, root_st.st_ino)
    if root_key in visited:
        stats.warnings.append(
            f"Dateisystem-Zyklus erkannt, überspringe Ordner: {safe_str(local_dir)}"
        )
        return []
    visited.add(root_key)

    members: List[TreeMember] = []
    stack: List[Tuple[Path, str]] = [(local_dir, "")]
    while stack:
        current, rel = stack.pop()
        try:
            children = sorted(current.iterdir(), key=lambda p: p.name.lower())
        except OSError as exc:
            stats.errors.append(
                f"Konnte lokalen Ordner nicht lesen {safe_str(current)}: {safe_str(exc)}"
            )
            continue
        for child in children:
            result = classify_entry(child, policy, stats)
            if result is None:
                continue
            kind, st = result
            child_rel = f"{rel}/{child.name}" if rel else child.name
            if kind == "dir":
                key = (st.st_dev, st.st_ino)
                if key in visited:
                    stats.warnings.append(
                        f"Dateisystem-Zyklus erkannt, überspringe Ordner: {safe_str(child)}"
                    )
                    continue
                visited.add(key)
                members.append(TreeMember(rel=child_rel, is_dir=True))
                stack.append((child, child_rel))
            else:
                members.append(
                    TreeMember(rel=child_rel, is_dir=False, dev=st.st_dev, ino=st.st_ino)
                )

    members.sort(key=lambda m: (m.rel.count("/"), m.rel))
    n_dirs = sum(1 for m in members if m.is_dir)
    n_files = len(members) - n_dirs
    stats.new_folders += 1 + n_dirs
    stats.new_files += n_files

    return [
        SyncAction(
            local_path=local_dir,
            remote_parent=remote_parent,
            reason="new_tree",
            details=f"Neuer Ordner ({n_dirs} Unterordner, {n_files} Dateien, gefiltert)",
            remote_name=effective_name if effective_name != local_dir.name else None,
            dev=root_st.st_dev,
            ino=root_st.st_ino,
            members=members,
        )
    ]


def list_remote_directory(
    remote_path: str,
    proton_bin: str = PROTON_DRIVE_BIN,
    retries: int = 3,
    timeout_sec: int = DEFAULT_LIST_TIMEOUT_SEC,
) -> Tuple[Optional[Dict[str, RemoteNode]], Optional[str]]:
    """
    Liest den Inhalt eines Remote-Ordners via `proton-drive filesystem list -j -- <remote_path>`.
    Gibt `(entries_dict, error_detail)` zurück.
    Beinhaltet Timeouts, geschlossenes `stdin` und Wiederholungsversuche bei temporären Sperren.
    """
    cmd = [proton_bin, "filesystem", "list", "-j", "--", remote_path]
    raw_items = None
    last_err = ""

    for attempt in range(retries):
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            last_err = f"Zeitüberschreitung nach {timeout_sec}s"
            if attempt < retries - 1:
                time.sleep(0.8 * (attempt + 1))
            continue
        except OSError as exc:
            return None, safe_str(exc)

        if proc.returncode == 0:
            stdout = proc.stdout.strip()
            if not stdout:
                return {}, None
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, list):
                    raw_items = parsed
                    break
                last_err = "Unerwartetes JSON-Format von proton-drive (keine Liste)"
            except json.JSONDecodeError as exc:
                last_err = f"Ungültiges JSON von proton-drive: {safe_str(exc)}"
        else:
            stderr_clean = safe_str(proc.stderr.strip())
            last_err = (
                f"Exit-Code {proc.returncode}"
                + (f": {stderr_clean[:240]}" if stderr_clean else "")
            )

        if attempt < retries - 1:
            time.sleep(0.8 * (attempt + 1))

    if raw_items is None:
        return None, last_err or "Unbekannter CLI-Fehler"

    entries: Dict[str, RemoteNode] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        name_obj = item.get("name") or {}
        if isinstance(name_obj, dict):
            name = name_obj.get("value")
        else:
            name = str(name_obj)
        if not name or not isinstance(name, str):
            continue

        node_type = item.get("type", "file")
        mod_time = parse_iso_timestamp(item.get("modificationTime"))

        claimed_mtime = None
        claimed_size = None
        claimed_sha1 = None
        claimed_sha256 = None
        active_rev = item.get("activeRevision")
        if isinstance(active_rev, dict):
            claimed_mtime = parse_iso_timestamp(
                active_rev.get("claimedModificationTime")
            )
            raw_size = active_rev.get("claimedSize")
            if (
                isinstance(raw_size, int)
                and not isinstance(raw_size, bool)
                and raw_size >= 0
            ):
                claimed_size = raw_size
            digests = active_rev.get("claimedDigests")
            if isinstance(digests, dict):
                raw_sha1 = digests.get("sha1")
                if is_valid_hex_digest(raw_sha1, 40):
                    claimed_sha1 = str(raw_sha1).lower()
                raw_sha256 = digests.get("sha256")
                if is_valid_hex_digest(raw_sha256, 64):
                    claimed_sha256 = str(raw_sha256).lower()

        entries[name] = RemoteNode(
            name=name,
            node_type=node_type,
            modification_time=mod_time,
            claimed_mtime=claimed_mtime,
            claimed_size=claimed_size,
            claimed_sha1=claimed_sha1,
            claimed_sha256=claimed_sha256,
        )
    return entries, None


def collect_sync_targets(
    dokumente_dir: Path,
    zotero_dir: Path,
    include_hidden: bool,
    stats: SyncStats,
    exclude_patterns: Sequence[str] = (),
    allowed_devs: FrozenSet[int] = frozenset(),
) -> List[Tuple[Path, str, str]]:
    """
    Bestimmt alle zu synchronisierenden Top-Level-Ordner unter Berücksichtigung
    der Ausschlussliste `exclude_patterns` und erlaubter Dateisysteme (`allowed_devs`).
    Rückgabe: Liste von Tupeln (resolved_local_folder_path, remote_parent_path, folder_name)
    """
    targets: List[Tuple[Path, str, str]] = []
    raw_dok = dokumente_dir.expanduser()
    raw_zot = zotero_dir.expanduser()
    resolved_dok = raw_dok.resolve()
    resolved_zot = raw_zot.resolve()
    base_dirs = [raw_dok, raw_zot]

    if resolved_dok.exists() and resolved_dok.is_dir():
        for entry in sorted(resolved_dok.iterdir(), key=lambda p: p.name.lower()):
            if entry.name.startswith(STAGING_PREFIX):
                continue
            if entry.name.startswith(".") and not include_hidden:
                continue
            try:
                st = os.lstat(entry)
            except OSError as exc:
                stats.errors.append(
                    f"Konnte Element nicht prüfen {safe_str(entry)}: {safe_str(exc)}"
                )
                continue
            if stat.S_ISLNK(st.st_mode):
                stats.skipped_symlinks += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                ok_name, reason = is_safe_node_name(entry.name)
                if not ok_name:
                    stats.errors.append(
                        f"Überspringe Top-Level-Ordner {safe_str(entry)}: {reason}"
                    )
                    continue
                if allowed_devs and st.st_dev not in allowed_devs:
                    stats.warnings.append(
                        f"Anderes Dateisystem / Mount-Point übersprungen: {safe_str(entry)} "
                        "(--cross-filesystems zum Einbeziehen)"
                    )
                    continue
                excluded, matched = is_excluded_path(entry, exclude_patterns, base_dirs)
                if excluded:
                    stats.excluded_folders.append((entry, matched or ""))
                    continue
                targets.append((entry, REMOTE_ROOT, entry.name))
            elif stat.S_ISREG(st.st_mode):
                stats.ignored_loose_files.append(entry)
    else:
        stats.errors.append(
            f"Dokumente-Ordner nicht gefunden: {safe_str(dokumente_dir)}"
        )

    if resolved_zot.exists() and resolved_zot.is_dir():
        # Falls ~/Zotero ein Symlink auf z. B. /mnt/data/zotero_profile ist, bleibt der Zielname "Zotero"
        logical_zot_name = (
            raw_zot.name
            if raw_zot.name and raw_zot.name not in (".", "..")
            else resolved_zot.name
        )
        ok_name, reason = is_safe_node_name(logical_zot_name)
        if not ok_name:
            stats.errors.append(
                f"Ungültiger Zotero-Zielordnername '{safe_str(logical_zot_name)}' (Pfad: {safe_str(zotero_dir)}): {reason}"
            )
        else:
            excluded, matched = is_excluded_path(
                raw_zot, exclude_patterns, base_dirs
            )
            if excluded:
                stats.excluded_folders.append((resolved_zot, matched or ""))
            else:
                targets.append((resolved_zot, REMOTE_ROOT, logical_zot_name))
    else:
        stats.errors.append(f"Zotero-Ordner nicht gefunden: {safe_str(zotero_dir)}")

    return targets


def should_upload_existing_file(
    local_file: Path,
    remote_node: RemoteNode,
    mtime_tolerance_sec: float = 1.0,
    warnings_out: Optional[List[str]] = None,
) -> Tuple[bool, str, str]:
    """
    Prüft für eine lokal und in der Cloud existierende Datei, ob sie hochgeladen
    werden soll.
    Gibt (should_upload, category, details) zurück.
    Kategorien:
      - "identical": gleicher Inhalt (Größe + Hash identisch)
      - "updated_file": PC-Version ist neuer als Cloud-Version und Inhalt unterscheidet sich
      - "remote_newer_or_equal": Cloud-Version ist neuer oder gleich alt
    """
    lst = os.lstat(local_file)
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise OSError(f"Keine reguläre Datei (oder Symlink): {safe_str(local_file)}")

    local_size = lst.st_size
    local_mtime = datetime.datetime.fromtimestamp(
        lst.st_mtime, tz=datetime.timezone.utc
    )
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    remote_mtime = remote_node.claimed_mtime
    if remote_mtime is not None and remote_mtime > now_utc + FUTURE_MTIME_SKEW_TOLERANCE:
        msg = (
            f"Verdächtiger Zukunfts-Zeitstempel in Cloud für {safe_str(local_file)} "
            f"(claimedModificationTime={remote_mtime.isoformat()})"
        )
        if (
            remote_node.modification_time is not None
            and remote_node.modification_time <= now_utc + FUTURE_MTIME_SKEW_TOLERANCE
        ):
            remote_mtime = remote_node.modification_time
            msg += f" -> nutze Server-modificationTime ({remote_mtime.isoformat()})"
        if warnings_out is not None:
            warnings_out.append(msg)
    elif remote_mtime is None:
        remote_mtime = remote_node.modification_time

    # 1. Wenn Cloud-Zeitstempel bekannt ist und die Cloud-Datei neuer oder gleich alt ist:
    #    Niemals eine neuere oder gleich alte Cloud-Datei überschreiben!
    if remote_mtime is not None:
        diff_seconds = (local_mtime - remote_mtime).total_seconds()
        if diff_seconds <= mtime_tolerance_sec:
            return (
                False,
                "remote_newer_or_equal",
                f"lokal={local_mtime.isoformat()} <= cloud={remote_mtime.isoformat()}",
            )

    # 2. Lokal ist neuer (oder Cloud hat keinen Zeitstempel):
    #    Prüfen, ob der Inhalt trotz neuerem Zeitstempel bereits identisch ist
    if (
        remote_node.claimed_size is not None
        and remote_node.claimed_size == local_size
        and (remote_node.claimed_sha256 or remote_node.claimed_sha1)
    ):
        local_sha1, local_sha256 = compute_digests(
            local_file, need_sha256=bool(remote_node.claimed_sha256)
        )
        sha256_ok = (
            remote_node.claimed_sha256 is None
            or local_sha256 == remote_node.claimed_sha256
        )
        sha1_ok = (
            remote_node.claimed_sha1 is None
            or local_sha1 == remote_node.claimed_sha1
        )
        if sha256_ok and sha1_ok:
            digest_preview = (local_sha256 or local_sha1)[:10]
            algo = "SHA-256" if remote_node.claimed_sha256 else "SHA-1"
            return (
                False,
                "identical",
                f"{algo} identisch ({digest_preview}...)",
            )

    remote_str = remote_mtime.isoformat() if remote_mtime else "unbekannt"
    return (
        True,
        "updated_file",
        f"lokal ({local_mtime.isoformat()}) > cloud ({remote_str})",
    )


def plan_directory_sync(
    local_dir: Path,
    remote_dir_path: str,
    proton_bin: str,
    executor: concurrent.futures.ThreadPoolExecutor,
    stats: SyncStats,
    policy: ScanPolicy,
    mtime_tolerance_sec: float = 1.0,
    list_timeout_sec: int = DEFAULT_LIST_TIMEOUT_SEC,
) -> List[SyncAction]:
    """
    Durchläuft `local_dir` ebenenweise (BFS) und nutzt parallele `filesystem list -j`
    Abfragen für bereits in der Cloud vorhandene Unterordner.
    Alle Elemente werden über `classify_entry` gefiltert.
    """
    actions: List[SyncAction] = []
    visited_inodes: Set[Tuple[int, int]] = set()

    try:
        root_st = os.lstat(local_dir)
        visited_inodes.add((root_st.st_dev, root_st.st_ino))
    except OSError as exc:
        stats.errors.append(
            f"Konnte lokalen Ordner nicht prüfen {safe_str(local_dir)}: {safe_str(exc)}"
        )
        return actions

    current_level: List[Tuple[Path, str]] = [(local_dir, remote_dir_path)]

    while current_level:
        future_to_pair = {
            executor.submit(
                list_remote_directory,
                r_path,
                proton_bin,
                3,
                list_timeout_sec,
            ): (l_dir, r_path)
            for l_dir, r_path in current_level
        }

        next_level: List[Tuple[Path, str]] = []

        for future in concurrent.futures.as_completed(future_to_pair):
            l_dir, r_path = future_to_pair[future]
            stats.folders_checked += 1
            remote_entries, err_detail = future.result()

            if remote_entries is None:
                detail_suffix = f" [{err_detail}]" if err_detail else ""
                stats.errors.append(
                    f"Konnte Remote-Ordner nicht auflisten: {safe_str(r_path)} "
                    f"(lokal: {safe_str(l_dir)}){detail_suffix}"
                )
                continue

            try:
                children = sorted(l_dir.iterdir(), key=lambda p: p.name.lower())
            except OSError as exc:
                stats.errors.append(
                    f"Konnte lokalen Ordner nicht lesen {safe_str(l_dir)}: {safe_str(exc)}"
                )
                continue

            for child in children:
                result = classify_entry(child, policy, stats)
                if result is None:
                    continue
                kind, child_st = result
                remote_node = remote_entries.get(child.name)

                if kind == "dir":
                    inode_key = (child_st.st_dev, child_st.st_ino)
                    if inode_key in visited_inodes:
                        stats.warnings.append(
                            f"Dateisystem-Zyklus erkannt, überspringe Ordner: {safe_str(child)}"
                        )
                        continue

                    if remote_node is None or remote_node.node_type != "folder":
                        actions.extend(
                            plan_new_folder_with_exclusions(
                                local_dir=child,
                                remote_parent=r_path,
                                policy=policy,
                                stats=stats,
                                _visited_inodes=visited_inodes,
                            )
                        )
                    else:
                        visited_inodes.add(inode_key)
                        try:
                            child_remote_path = join_remote_path(r_path, child.name)
                        except ValueError as exc:
                            stats.errors.append(str(exc))
                            continue
                        next_level.append((child, child_remote_path))
                    continue

                # kind == "file"
                if remote_node is None:
                    stats.new_files += 1
                    actions.append(
                        SyncAction(
                            local_path=child,
                            remote_parent=r_path,
                            reason="new_file",
                            details="Neue Datei",
                            dev=child_st.st_dev,
                            ino=child_st.st_ino,
                        )
                    )
                elif remote_node.node_type == "file":
                    try:
                        upload_needed, category, detail = should_upload_existing_file(
                            child,
                            remote_node,
                            mtime_tolerance_sec=mtime_tolerance_sec,
                            warnings_out=stats.warnings,
                        )
                    except OSError as exc:
                        stats.errors.append(
                            f"Fehler beim Lesen von {safe_str(child)}: {safe_str(exc)}"
                        )
                        continue

                    if upload_needed:
                        stats.updated_files += 1
                        actions.append(
                            SyncAction(
                                local_path=child,
                                remote_parent=r_path,
                                reason="updated_file",
                                details=detail,
                                dev=child_st.st_dev,
                                ino=child_st.st_ino,
                            )
                        )
                    elif category == "identical":
                        stats.skipped_identical += 1
                    else:
                        stats.skipped_remote_newer_or_equal += 1
                else:
                    stats.warnings.append(
                        f"Typkonflikt: lokal Datei, in der Cloud Ordner – übersprungen: {safe_str(child)}"
                    )

        current_level = next_level

    return actions


# --------------------------------------------------------------------------------------
# Ausführung: Verifikation, Staging, CLI-Aufrufe
# --------------------------------------------------------------------------------------


def _check_parents_not_symlinks(local_path: Path, allowed_roots: Sequence[Path]) -> Optional[str]:
    """Prüft alle Elternordner bis zur erlaubten Wurzel auf nachträgliche Symlinks."""
    matched_root: Optional[Path] = None
    for root in allowed_roots:
        try:
            local_path.relative_to(root)
            matched_root = root
            break
        except ValueError:
            continue
    if matched_root is None:
        return f"Pfad liegt außerhalb der erlaubten Quellordner: {safe_str(local_path)}"

    cur = local_path.parent
    while len(cur.parts) >= len(matched_root.parts):
        try:
            cur_st = os.lstat(cur)
        except OSError as exc:
            return f"Elternordner nicht prüfbar {safe_str(cur)}: {safe_str(exc)}"
        if stat.S_ISLNK(cur_st.st_mode):
            return f"TOCTOU-Schutz: Elternordner {safe_str(cur)} wurde durch Symlink ersetzt!"
        if cur == matched_root:
            break
        cur = cur.parent
    return None


def _verify_file_identity(path: Path, dev: int, ino: int) -> None:
    """Stellt sicher, dass `path` exakt die beim Scan geprüfte reguläre Datei (Inode) ist."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ToctouError(
            f"Lokale Datei vor Upload verschwunden/unlesbar {safe_str(path)}: {safe_str(exc)}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise ToctouError(f"TOCTOU-Schutz: {safe_str(path)} wurde durch einen Symlink ersetzt!")
    if not stat.S_ISREG(st.st_mode):
        raise ToctouError(f"TOCTOU-Schutz: {safe_str(path)} ist keine reguläre Datei mehr!")
    if ino and (st.st_dev, st.st_ino) != (dev, ino):
        raise ToctouError(
            f"TOCTOU-Schutz: {safe_str(path)} wurde seit dem Scan durch eine andere Datei ersetzt!"
        )


def verify_action_before_execution(
    action: SyncAction,
    allowed_roots: Sequence[Path] = (),
) -> Tuple[bool, str]:
    """
    TOCTOU-Schutz unmittelbar vor dem Aufruf von `proton-drive`:
    Prüft per `lstat`, dass das Element exakt dem beim Scan geprüften Inode entspricht
    und weder das Ziel selbst noch ein Zwischenordner durch einen Symlink ersetzt wurde.
    """
    local_path = action.local_path
    if not local_path.is_absolute():
        return False, f"Relativer lokaler Pfad verweigert: {safe_str(local_path)}"

    if not (
        action.remote_parent == REMOTE_ROOT
        or action.remote_parent.startswith(REMOTE_ROOT + "/")
    ):
        return (
            False,
            f"Unsicheres Remote-Ziel außerhalb von {REMOTE_ROOT}: {safe_str(action.remote_parent)}",
        )

    ok_name, name_reason = is_safe_node_name(action.target_name)
    if not ok_name:
        return False, f"Unsicherer Dateiname {safe_str(local_path)}: {name_reason}"

    try:
        lst = os.lstat(local_path)
    except OSError as exc:
        return (
            False,
            f"Lokales Element vor Upload verschwunden/unlesbar {safe_str(local_path)}: {safe_str(exc)}",
        )

    if stat.S_ISLNK(lst.st_mode):
        return False, f"TOCTOU-Schutz: {safe_str(local_path)} wurde durch einen Symlink ersetzt!"

    expect_dir = action.reason == "new_tree"
    if expect_dir and not stat.S_ISDIR(lst.st_mode):
        return False, f"TOCTOU-Schutz: {safe_str(local_path)} ist kein Verzeichnis mehr!"
    if not expect_dir and not stat.S_ISREG(lst.st_mode):
        return False, f"TOCTOU-Schutz: {safe_str(local_path)} ist keine reguläre Datei mehr!"

    if action.ino and (lst.st_dev, lst.st_ino) != (action.dev, action.ino):
        return (
            False,
            f"TOCTOU-Schutz: {safe_str(local_path)} wurde seit dem Scan durch ein anderes Element ersetzt!",
        )

    if allowed_roots:
        parent_err = _check_parents_not_symlinks(local_path, allowed_roots)
        if parent_err:
            return False, parent_err

    return True, ""


def _remove_staging_tree(path: Path) -> List[str]:
    """
    Entfernt einen Staging-Bereich. Er enthält ausschließlich selbst angelegte Ordner und
    Hardlinks – das Entfernen eines Hardlinks löscht niemals die Originaldatei.
    Symlinks werden nie verfolgt.
    """
    errors: List[str] = []
    if not os.path.lexists(path):
        return errors
    for dirpath, dirnames, filenames in os.walk(path, topdown=False, followlinks=False):
        for fname in filenames:
            try:
                os.unlink(os.path.join(dirpath, fname))
            except OSError as exc:
                errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
        for dname in dirnames:
            dpath = os.path.join(dirpath, dname)
            try:
                if os.path.islink(dpath):
                    os.unlink(dpath)
                else:
                    os.rmdir(dpath)
            except OSError as exc:
                errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
    try:
        os.rmdir(path)
    except OSError as exc:
        errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
    return errors


def _link_verified(
    src: Path,
    dst: Path,
    dev: int,
    ino: int,
    allowed_roots: Sequence[Path] = (),
) -> None:
    """
    Legt `dst` als Hardlink auf `src` an und stellt vorher UND nachher sicher, dass exakt
    der beim Scan geprüfte Inode verlinkt wurde und kein Elternordner zum Symlink wurde.
    Wird `src` dazwischen gegen einen Symlink oder eine andere Datei getauscht, schlägt
    der Abgleich fehl (ToctouError). Andere Fehler (z. B. EXDEV, EPERM) werden als OSError weitergereicht.
    """
    if allowed_roots:
        parent_err = _check_parents_not_symlinks(src, allowed_roots)
        if parent_err:
            raise ToctouError(parent_err)
    _verify_file_identity(src, dev, ino)
    os.link(src, dst, follow_symlinks=False)
    st = os.lstat(dst)
    if stat.S_ISLNK(st.st_mode) or (st.st_dev, st.st_ino) != (dev, ino):
        os.unlink(dst)
        raise ToctouError(
            f"TOCTOU-Schutz: {safe_str(src)} wurde während des Stagings ausgetauscht!"
        )


def _private_cache_dir() -> Optional[Path]:
    cache_dir = Path.home() / ".cache" / "proton-sync"
    try:
        cache_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        st = os.lstat(cache_dir)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            return None
        if st.st_mode & 0o077:
            os.chmod(cache_dir, 0o700)
        return cache_dir
    except OSError:
        return None


class StagingArea:
    """
    Privater Staging-Bereich (`0700`, zufälliger Name) aus Hardlinks auf demselben
    Dateisystem (bevorzugt unter `~/.cache/proton-sync`, sonst in der Quellwurzel).
    `proton-drive` erhält nur Pfade in diesem Bereich, sodass nachträglich in die
    echten Ordner gelegte Dateien/Symlinks niemals mit hochgeladen werden.
    """

    def __init__(self, roots: Sequence[Path], enabled: bool = True) -> None:
        self.roots = [Path(r) for r in roots]
        self.enabled = enabled
        self._base_dirs: Dict[int, Path] = {}
        self._failed_devs: Set[int] = set()
        self._counter = 0

    def _base_for_dev(self, dev: int) -> Optional[Path]:
        if not self.enabled or dev in self._failed_devs:
            return None
        if dev in self._base_dirs:
            return self._base_dirs[dev]

        candidates: List[Path] = []
        cache_dir = _private_cache_dir()
        if cache_dir is not None:
            candidates.append(cache_dir)
        candidates.extend(self.roots)

        for root in candidates:
            try:
                st = os.lstat(root)
            except OSError:
                continue
            if not stat.S_ISDIR(st.st_mode) or st.st_dev != dev:
                continue
            try:
                base = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=str(root)))
            except OSError:
                continue
            self._base_dirs[dev] = base
            return base
        self._failed_devs.add(dev)
        return None

    def new_slot(self, dev: int) -> Optional[Path]:
        base = self._base_for_dev(dev)
        if base is None:
            return None
        self._counter += 1
        slot = base / f"{self._counter:06d}"
        try:
            slot.mkdir(mode=0o700)
        except OSError:
            return None
        return slot

    def discard(self, slot: Optional[Path]) -> List[str]:
        if slot is None:
            return []
        return _remove_staging_tree(slot)

    def cleanup(self) -> List[str]:
        errors: List[str] = []
        for base in list(self._base_dirs.values()):
            errors.extend(_remove_staging_tree(base))
        self._base_dirs.clear()
        return errors

    def __enter__(self) -> "StagingArea":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()


def find_stale_staging_dirs(roots: Sequence[Path]) -> List[Path]:
    stale: List[Path] = []
    for root in roots:
        try:
            for entry in os.scandir(root):
                if entry.name.startswith(STAGING_PREFIX):
                    stale.append(Path(entry.path))
        except OSError:
            continue
    return stale


_LINE_SPLIT_RE = re.compile(rb"[\r\n]")


def run_cli_streaming(cmd: Sequence[str], timeout_sec: Optional[int] = None) -> Tuple[int, bool]:
    """
    Führt `cmd` aus, liest stdout/stderr zeilenweise und gibt jede Zeile ausschließlich
    über `safe_str` bereinigt aus (keine Terminal-Steuerzeichen aus Dateinamen).
    `timeout_sec=None` bzw. `0` bedeutet kein Zeitlimit.
    Gibt `(returncode, timed_out)` zurück.
    """
    proc = subprocess.Popen(
        list(cmd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = threading.Event()

    def _kill_group() -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def _on_timeout() -> None:
        timed_out.set()
        _kill_group()

    timer: Optional[threading.Timer] = None
    if timeout_sec:
        timer = threading.Timer(timeout_sec, _on_timeout)
        timer.daemon = True
        timer.start()

    last_line: Optional[str] = None

    def _emit(raw: bytes) -> None:
        nonlocal last_line
        line = raw.decode("utf-8", errors="replace").strip()
        if line and line != last_line:
            print(f"    {safe_str(line)}", flush=True)
            last_line = line

    try:
        assert proc.stdout is not None
        buf = b""
        while True:
            chunk = proc.stdout.read1(4096)
            if not chunk:
                break
            buf += chunk
            parts = _LINE_SPLIT_RE.split(buf)
            buf = parts.pop()
            for part in parts:
                _emit(part)
        if buf:
            _emit(buf)
        returncode = proc.wait()
    except BaseException:
        _kill_group()
        proc.wait()
        raise
    finally:
        if timer is not None:
            timer.cancel()
        if proc.stdout is not None:
            proc.stdout.close()

    return returncode, timed_out.is_set()


def _cli_upload(
    proton_bin: str,
    conflict_strategy: str,
    local_paths: Sequence[str],
    remote_parent: str,
    timeout_sec: Optional[int],
) -> Optional[str]:
    cmd = [
        proton_bin,
        "filesystem",
        "upload",
        "-f",
        conflict_strategy,
        "-d",
        "merge",
        "--",
        *local_paths,
        remote_parent,
    ]
    print(f"-> Lade {len(local_paths)} Element(e) hoch nach {safe_str(remote_parent)} ...")
    try:
        rc, timed_out = run_cli_streaming(cmd, timeout_sec)
    except OSError as exc:
        return f"Prozessfehler beim Upload nach {safe_str(remote_parent)}: {safe_str(exc)}"
    if timed_out:
        return f"Zeitüberschreitung ({timeout_sec}s) beim Upload nach {safe_str(remote_parent)}"
    if rc != 0:
        return f"Upload fehlgeschlagen (Exit-Code {rc}) für Ziel {safe_str(remote_parent)}"
    return None


def _cli_create_folder(
    proton_bin: str,
    remote_parent: str,
    name: str,
    timeout_sec: Optional[int],
) -> Optional[str]:
    try:
        join_remote_path(remote_parent, name)
    except ValueError as exc:
        return str(exc)
    cmd = [proton_bin, "filesystem", "create-folder", "--", remote_parent, name]
    try:
        rc, timed_out = run_cli_streaming(cmd, timeout_sec)
    except OSError as exc:
        return f"Prozessfehler beim Anlegen von {safe_str(name)}: {safe_str(exc)}"
    if timed_out:
        return f"Zeitüberschreitung ({timeout_sec}s) beim Anlegen von {safe_str(name)} in {safe_str(remote_parent)}"
    if rc != 0:
        return (
            f"Ordner-Erstellung fehlgeschlagen (Exit-Code {rc}) für {safe_str(name)} "
            f"in {safe_str(remote_parent)}"
        )
    return None


def _execute_new_tree(
    action: SyncAction,
    proton_bin: str,
    conflict_strategy: str,
    batch_size: int,
    allowed_roots: Sequence[Path],
    staging: Optional[StagingArea],
    timeout_sec: Optional[int],
) -> List[str]:
    ok, err = verify_action_before_execution(action, allowed_roots)
    if not ok:
        return [err]

    # 1. Bevorzugt: kompletter Upload aus dem privaten Hardlink-Staging (ein CLI-Aufruf)
    slot = staging.new_slot(action.dev) if staging is not None else None
    if slot is not None:
        staged_errors: List[str] = []
        tree_root = slot / action.target_name
        try:
            tree_root.mkdir(mode=0o700)
            for member in action.members:
                dst = tree_root / member.rel
                if member.is_dir:
                    dst.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                try:
                    _link_verified(
                        action.local_path / member.rel,
                        dst,
                        member.dev,
                        member.ino,
                        allowed_roots=allowed_roots,
                    )
                except ToctouError as exc:
                    staged_errors.append(str(exc))
        except OSError:
            # z. B. EXDEV (Mitglied auf anderem Dateisystem) oder EPERM (protected_hardlinks)
            staging.discard(slot)
        else:
            upload_err = _cli_upload(
                proton_bin, conflict_strategy, [str(tree_root)], action.remote_parent, timeout_sec
            )
            staged_errors.extend(staging.discard(slot))
            if upload_err:
                staged_errors.append(upload_err)
            return staged_errors

    # 2. Fallback ohne Staging: Ordner einzeln anlegen, Dateien einzeln verifiziert hochladen
    errors: List[str] = []
    try:
        remote_root = join_remote_path(action.remote_parent, action.target_name)
    except ValueError as exc:
        return [str(exc)]
    create_err = _cli_create_folder(proton_bin, action.remote_parent, action.target_name, timeout_sec)
    if create_err:
        return [create_err]

    remote_dirs: Dict[str, str] = {"": remote_root}
    for member in action.members:
        if not member.is_dir:
            continue
        parent_rel, _, name = member.rel.rpartition("/")
        parent_remote = remote_dirs.get(parent_rel)
        if parent_remote is None:
            continue
        create_err = _cli_create_folder(proton_bin, parent_remote, name, timeout_sec)
        if create_err:
            errors.append(create_err)
            continue
        remote_dirs[member.rel] = join_remote_path(parent_remote, name)

    files_by_parent: Dict[str, List[TreeMember]] = {}
    for member in action.members:
        if not member.is_dir:
            parent_rel = member.rel.rpartition("/")[0]
            files_by_parent.setdefault(parent_rel, []).append(member)

    for parent_rel, files in files_by_parent.items():
        remote_target = remote_dirs.get(parent_rel)
        if remote_target is None:
            continue
        verified: List[str] = []
        for member in files:
            src = action.local_path / member.rel
            try:
                _verify_file_identity(src, member.dev, member.ino)
            except ToctouError as exc:
                errors.append(str(exc))
                continue
            parent_err = _check_parents_not_symlinks(src, allowed_roots) if allowed_roots else None
            if parent_err:
                errors.append(parent_err)
                continue
            verified.append(str(src))
        for i in range(0, len(verified), batch_size):
            upload_err = _cli_upload(
                proton_bin, conflict_strategy, verified[i : i + batch_size], remote_target, timeout_sec
            )
            if upload_err:
                errors.append(upload_err)
    return errors


def _execute_file_batch(
    batch: Sequence[SyncAction],
    remote_parent: str,
    proton_bin: str,
    conflict_strategy: str,
    allowed_roots: Sequence[Path],
    staging: Optional[StagingArea],
    timeout_sec: Optional[int],
) -> List[str]:
    errors: List[str] = []
    upload_paths: List[str] = []
    slots: Dict[int, Optional[Path]] = {}

    for action in batch:
        ok, err = verify_action_before_execution(action, allowed_roots)
        if not ok:
            errors.append(err)
            continue

        staged_path: Optional[Path] = None
        if staging is not None:
            if action.dev not in slots:
                slots[action.dev] = staging.new_slot(action.dev)
            slot = slots[action.dev]
            if slot is not None:
                dst = slot / action.target_name
                try:
                    _link_verified(
                        action.local_path,
                        dst,
                        action.dev,
                        action.ino,
                        allowed_roots=allowed_roots,
                    )
                    staged_path = dst
                except ToctouError as exc:
                    errors.append(str(exc))
                    continue
                except OSError:
                    staged_path = None  # Fallback auf direkten, frisch verifizierten Pfad
        upload_paths.append(str(staged_path or action.local_path))

    try:
        if upload_paths:
            upload_err = _cli_upload(
                proton_bin, conflict_strategy, upload_paths, remote_parent, timeout_sec
            )
            if upload_err:
                errors.append(upload_err)
    finally:
        if staging is not None:
            for slot in slots.values():
                errors.extend(staging.discard(slot))
    return errors


def execute_upload_batches(
    actions: List[SyncAction],
    proton_bin: str,
    conflict_strategy: str = "create-new-revision",
    batch_size: int = 50,
    dry_run: bool = False,
    verbose: bool = False,
    allowed_roots: Sequence[Path] = (),
    upload_timeout_sec: Optional[int] = None,
    use_staging: bool = True,
) -> List[str]:
    """
    Führt alle geplanten Aktionen aus:
    - `new_tree`: Neuer Ordner wird aus einem privaten Hardlink-Staging in einem Aufruf
      hochgeladen (Fallback: Ordner einzeln anlegen + verifizierte Einzeldateien).
    - `new_file` / `updated_file`: gruppiert nach Zielordner via
      `proton-drive filesystem upload -f <strategy> -d merge -- <pfade...> <remote_parent>`
    """
    errors: List[str] = []
    if not actions:
        return errors

    tags = {
        "new_tree": "[NEUER ORDNER] ",
        "new_file": "[NEUE DATEI]   ",
        "updated_file": "[AKTUALISIERT] ",
    }

    if dry_run or verbose:
        for a in actions:
            print(
                f"  {tags.get(a.reason, '[UPLOAD]       ')}{safe_str(a.local_path)} -> "
                f"{safe_str(a.remote_parent)} ({safe_str(a.details)})"
            )
            if verbose and a.reason == "new_tree":
                for m in a.members:
                    marker = "/" if m.is_dir else ""
                    print(f"        + {safe_str(m.rel)}{marker}")
    if dry_run:
        return errors

    staging = StagingArea(allowed_roots, enabled=use_staging and bool(allowed_roots))
    try:
        for a in (x for x in actions if x.reason == "new_tree"):
            errors.extend(
                _execute_new_tree(
                    a,
                    proton_bin,
                    conflict_strategy,
                    batch_size,
                    allowed_roots,
                    staging if staging.enabled else None,
                    upload_timeout_sec,
                )
            )

        grouped: Dict[str, List[SyncAction]] = {}
        for a in actions:
            if a.reason in ("new_file", "updated_file"):
                grouped.setdefault(a.remote_parent, []).append(a)

        for remote_parent, group in grouped.items():
            for i in range(0, len(group), batch_size):
                errors.extend(
                    _execute_file_batch(
                        group[i : i + batch_size],
                        remote_parent,
                        proton_bin,
                        conflict_strategy,
                        allowed_roots,
                        staging if staging.enabled else None,
                        upload_timeout_sec,
                    )
                )
    finally:
        errors.extend(staging.cleanup())

    return errors


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Synchronisiert alle Unterordner in ~/Dokumente (ohne lose Dateien) "
            "sowie ~/Zotero mit Proton Drive (/my-files)."
        )
    )
    parser.add_argument(
        "--dokumente",
        type=Path,
        default=DEFAULT_DOKUMENTE,
        help=f"Pfad zum Dokumente-Ordner (Standard: {DEFAULT_DOKUMENTE})",
    )
    parser.add_argument(
        "--zotero",
        type=Path,
        default=DEFAULT_ZOTERO,
        help=f"Pfad zum Zotero-Ordner (Standard: {DEFAULT_ZOTERO})",
    )
    parser.add_argument(
        "--exclude",
        "-x",
        action="append",
        default=[],
        metavar="MUSTER",
        help=(
            "Schließt bestimmte Ordner oder Dateien von der Synchronisation aus "
            "(Groß-/Kleinschreibung egal). Mehrfach nutzbar oder kommagetrennt "
            "(z. B. `-x Videos -x *.kdbx` oder `--exclude Videos,node_modules`; `\\,` für Komma im Namen)."
        ),
    )
    parser.add_argument(
        "--exclude-file",
        type=Path,
        default=None,
        help=(
            f"Explizite Datei mit Ausschlussmustern (Fail-Closed bei Nichtvorhandensein; "
            f"Standard ohne Flag: {DEFAULT_EXCLUDE_FILE} falls vorhanden)."
        ),
    )
    parser.add_argument(
        "--only",
        type=str,
        default=None,
        help="Optional: Nur einen bestimmten Top-Level-Ordnernamen synchronisieren (z. B. 'Zotero' oder 'Projekte').",
    )
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Simuliert den Durchlauf und zeigt alle geplanten Uploads an, ohne Änderungen vorzunehmen.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Zeigt jede hochzuladende Datei und jeden Ordner detailliert an.",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Versteckte Dateien und Ordner (beginnend mit '.') ebenfalls synchronisieren.",
    )
    parser.add_argument(
        "--allow-hardlinks",
        action="store_true",
        help="Dateien mit mehreren Hardlinks ebenfalls hochladen (Standard: überspringen).",
    )
    parser.add_argument(
        "--cross-filesystems",
        action="store_true",
        help="Auch in eingehängte Laufwerke / andere Dateisysteme innerhalb der Quellordner absteigen.",
    )
    parser.add_argument(
        "--no-staging",
        action="store_true",
        help="Kein Hardlink-Staging verwenden (langsamer, kleines Rest-TOCTOU-Fenster).",
    )
    parser.add_argument(
        "--allow-live-zotero",
        action="store_true",
        help="Erzwingt den Upload von zotero.sqlite auch dann, wenn Zotero gerade geöffnet ist.",
    )
    parser.add_argument(
        "--no-lock",
        action="store_true",
        help="Deaktiviert die exklusive Instanz-Sperre (flock).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=2,
        help=f"Anzahl paralleler Abfragen für Remote-Ordnerlisten (1–{MAX_WORKERS_LIMIT}, Standard: 2).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Maximale Laufzeit pro Upload-Aufruf in Sekunden (Standard: 0 = unbegrenzt).",
    )
    parser.add_argument(
        "--file-conflict-strategy",
        choices=["create-new-revision", "replace"],
        default="create-new-revision",
        help=(
            "Konfliktstrategie für ältere Cloud-Dateien: "
            "'create-new-revision' (Standard, legt neue Dateiversion an ohne Löschen) "
            "oder 'replace' (verschiebt Cloud-Datei in den Papierkorb; erfordert --allow-trash)."
        ),
    )
    parser.add_argument(
        "--allow-trash",
        action="store_true",
        help="Erlaubt die Strategie 'replace', die Cloud-Dateien in den Papierkorb verschiebt.",
    )
    parser.add_argument(
        "--proton-bin",
        type=str,
        default=PROTON_DRIVE_BIN,
        help=f"Pfad zur proton-drive ausführbaren Datei (Standard: {PROTON_DRIVE_BIN}).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.file_conflict_strategy == "replace" and not args.allow_trash:
        print(
            "FEHLER: '--file-conflict-strategy replace' verschiebt Cloud-Dateien in den Papierkorb "
            "und widerspricht der Kein-Löschen-Garantie. Bitte zusätzlich '--allow-trash' angeben.",
            file=sys.stderr,
        )
        return 2

    ok_bin, resolved_proton_bin, bin_err = validate_proton_binary(args.proton_bin)
    if not ok_bin or resolved_proton_bin is None:
        print(f"FEHLER: {bin_err}", file=sys.stderr)
        return 2

    explicit_exclude = args.exclude_file is not None
    effective_exclude_file = (
        args.exclude_file if explicit_exclude else DEFAULT_EXCLUDE_FILE
    )

    try:
        exclude_patterns = load_exclude_patterns(
            cli_excludes=args.exclude,
            exclude_file=effective_exclude_file,
            require_exclude_file=explicit_exclude,
            extra_exclude_files=(
                DEFAULT_USER_EXCLUDE_FILE,
                DEFAULT_LOCAL_EXCLUDE_FILE,
            ),
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(
            f"FEHLER beim Laden der Ausschlussdatei (Fail-Closed-Abbruch): {safe_str(exc)}",
            file=sys.stderr,
        )
        return 2

    use_lock = not args.no_lock and not args.dry_run
    try:
        with SingleInstanceLock(enabled=use_lock):
            return _run_sync_session(
                args=args,
                proton_bin=resolved_proton_bin,
                exclude_patterns=exclude_patterns,
            )
    except RuntimeError as exc:
        print(f"FEHLER: {safe_str(exc)}", file=sys.stderr)
        return 3
    except PermissionError as exc:
        print(f"FEHLER bei Lock-Initialisierung: {safe_str(exc)}", file=sys.stderr)
        return 3


def _run_sync_session(
    *,
    args: argparse.Namespace,
    proton_bin: str,
    exclude_patterns: Sequence[str],
) -> int:
    raw_dok = args.dokumente.expanduser()
    raw_zot = args.zotero.expanduser()
    resolved_dok = raw_dok.resolve()
    resolved_zot = raw_zot.resolve()
    base_dirs = [raw_dok, raw_zot]
    allowed_roots = [resolved_dok, resolved_zot]

    allowed_devs: Set[int] = set()
    if not args.cross_filesystems:
        for root in allowed_roots:
            try:
                allowed_devs.add(os.stat(root).st_dev)
            except OSError:
                pass

    stats = SyncStats()

    search_staging_roots: List[Path] = list(allowed_roots)
    cache_dir = _private_cache_dir()
    if cache_dir is not None and cache_dir not in search_staging_roots:
        search_staging_roots.append(cache_dir)

    for stale in find_stale_staging_dirs(search_staging_roots):
        if not args.dry_run and not args.no_lock:
            cleanup_errs = _remove_staging_tree(stale)
            if cleanup_errs:
                stats.warnings.extend(cleanup_errs)
            else:
                stats.warnings.append(
                    f"Verwaister Staging-Ordner eines früheren abgebrochenen Laufs automatisch bereinigt: {safe_str(stale)}"
                )
        else:
            stats.warnings.append(
                f"Verwaister Staging-Ordner eines abgebrochenen Laufs gefunden: {safe_str(stale)} – "
                "wird beim nächsten regulären Lauf mit aktivem Lock automatisch bereinigt."
            )

    targets = collect_sync_targets(
        dokumente_dir=raw_dok,
        zotero_dir=raw_zot,
        include_hidden=args.include_hidden,
        stats=stats,
        exclude_patterns=exclude_patterns,
        allowed_devs=frozenset(allowed_devs),
    )

    if args.only:
        targets = [t for t in targets if t[2] == args.only]
        if not targets:
            print(
                f"FEHLER: Kein aktiver Zielordner mit dem Namen '{safe_str(args.only)}' gefunden "
                "(eventuell existiert er nicht oder wurde ausgeschlossen).",
                file=sys.stderr,
            )
            return 2

    locked_skip_files: Set[Path] = set()
    if not args.allow_live_zotero and any(t[0] == resolved_zot for t in targets):
        zotero_reason = zotero_db_state(resolved_zot)
        if zotero_reason:
            for side_name in ZOTERO_SQLITE_SIDE_FILES:
                candidate = resolved_zot / side_name
                if os.path.lexists(candidate):
                    locked_skip_files.add(candidate.resolve())
            stats.warnings.append(
                f"zotero.sqlite* übersprungen ({zotero_reason}), um korrupte Backups zu "
                "verhindern (--allow-live-zotero zum Erzwingen)."
            )

    policy = ScanPolicy(
        include_hidden=args.include_hidden,
        exclude_patterns=tuple(exclude_patterns),
        base_dirs=tuple(base_dirs),
        locked_skip_files=frozenset(locked_skip_files),
        allow_hardlinks=args.allow_hardlinks,
        allowed_devs=frozenset(allowed_devs),
    )

    workers = min(max(1, args.workers), MAX_WORKERS_LIMIT)
    upload_timeout: Optional[int] = args.timeout if args.timeout and args.timeout > 0 else None

    mode_label = "TROCKENLAUF (DRY-RUN)" if args.dry_run else "LIVE-SYNCHRONISATION"
    print(f"=== Proton Drive Synchronisation ({mode_label}) ===")
    print(
        f"Dokumente-Quelle : {safe_str(resolved_dok)} (nur Unterordner, keine losen Dateien)"
    )
    print(f"Zotero-Quelle    : {safe_str(resolved_zot)}")
    print(f"Cloud-Ziel       : {REMOTE_ROOT}")
    print(f"Proton-Binary    : {safe_str(proton_bin)}")
    print(
        f"Konflikt-Modus   : -f {args.file_conflict_strategy} -d merge"
        + (" (keine Löschungen!)" if args.file_conflict_strategy != "replace" else " (PAPIERKORB ERLAUBT!)")
    )
    if exclude_patterns:
        print(
            f"Ausschluss-Muster: {', '.join(safe_str(p) for p in exclude_patterns)}"
        )

    if stats.ignored_loose_files:
        ignored_names = ", ".join(safe_str(p.name) for p in stats.ignored_loose_files)
        print(
            f"Ignorierte lose Dateien in {safe_str(resolved_dok)} "
            f"({len(stats.ignored_loose_files)}): {ignored_names}"
        )
    print()

    # 1. Top-Level /my-files abfragen
    print(f"Prüfe Cloud-Hauptverzeichnis {REMOTE_ROOT} ...")
    root_entries, root_err = list_remote_directory(
        REMOTE_ROOT,
        proton_bin=proton_bin,
        timeout_sec=DEFAULT_LIST_TIMEOUT_SEC,
    )
    if root_entries is None:
        detail = f" ({root_err})" if root_err else ""
        print(
            f"FEHLER: Konnte {REMOTE_ROOT} in Proton Drive nicht abfragen{detail}. "
            "Bitte prüfe die Anmeldung via `proton-drive auth login`.",
            file=sys.stderr,
        )
        return 1
    stats.folders_checked += 1

    all_actions: List[SyncAction] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for local_folder, remote_parent, folder_name in targets:
            remote_node = root_entries.get(folder_name)
            try:
                remote_folder_path = join_remote_path(remote_parent, folder_name)
            except ValueError as exc:
                stats.errors.append(str(exc))
                continue

            if remote_node is None or remote_node.node_type != "folder":
                print(
                    f"[+] Neuer Top-Level-Ordner: {safe_str(local_folder)} -> {safe_str(remote_folder_path)}"
                )
                all_actions.extend(
                    plan_new_folder_with_exclusions(
                        local_dir=local_folder,
                        remote_parent=remote_parent,
                        policy=policy,
                        stats=stats,
                        remote_name=folder_name,
                    )
                )
            else:
                print(
                    f"[*] Vergleiche Ordner: {safe_str(local_folder)} <-> {safe_str(remote_folder_path)} ..."
                )
                all_actions.extend(
                    plan_directory_sync(
                        local_dir=local_folder,
                        remote_dir_path=remote_folder_path,
                        proton_bin=proton_bin,
                        executor=executor,
                        stats=stats,
                        policy=policy,
                        list_timeout_sec=DEFAULT_LIST_TIMEOUT_SEC,
                    )
                )

    if stats.excluded_folders:
        print("\nAusgeschlossene Ordner:")
        for folder_path, pattern in stats.excluded_folders:
            print(f"  [-] {safe_str(folder_path)} (Muster: '{safe_str(pattern)}')")

    if stats.excluded_files:
        print("\nAusgeschlossene Dateien:")
        for file_path, pattern in stats.excluded_files:
            print(f"  [-] {safe_str(file_path)} (Muster: '{safe_str(pattern)}')")

    print()
    print("=== Geplante Aktionen ===")
    print(f"Geprüfte Cloud-Ordner                 : {stats.folders_checked}")
    print(f"Ausgeschlossene Ordner                : {len(stats.excluded_folders)}")
    print(f"Ausgeschlossene Einzeldateien         : {len(stats.excluded_files)}")
    print(f"Übersprungene Symlinks                : {stats.skipped_symlinks}")
    print(f"Übersprungene Spezialdateien          : {stats.skipped_special}")
    print(f"Neue Ordner                           : {stats.new_folders}")
    print(f"Neue Einzeldateien                    : {stats.new_files}")
    print(f"Aktualisierte Dateien (PC > Cloud)    : {stats.updated_files}")
    print(f"Übersprungen (Inhalt/Hash identisch)  : {stats.skipped_identical}")
    print(f"Übersprungen (Cloud neuer/gleich alt) : {stats.skipped_remote_newer_or_equal}")
    print(f"Ignorierte lose Dateien in Dokumente  : {len(stats.ignored_loose_files)}")
    print()

    if all_actions:
        upload_errors = execute_upload_batches(
            actions=all_actions,
            proton_bin=proton_bin,
            conflict_strategy=args.file_conflict_strategy,
            dry_run=args.dry_run,
            verbose=args.verbose,
            allowed_roots=allowed_roots,
            upload_timeout_sec=upload_timeout,
            use_staging=not args.no_staging,
        )
        stats.errors.extend(upload_errors)
    else:
        print("Alles auf dem neuesten Stand – keine Uploads erforderlich.")

    if stats.warnings:
        print("\n=== Sicherheitshinweise / Warnungen ===", file=sys.stderr)
        for warn in stats.warnings:
            print(f"  [!] {warn}", file=sys.stderr)

    if stats.errors:
        print("\n=== Fehler ===", file=sys.stderr)
        for err in stats.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("\nSynchronisation erfolgreich abgeschlossen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
