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
  `--exclude` / `-x` von der Synchronisation ausgeschlossen werden.
- Explizit per `--exclude-file` angegebene oder fehlerhafte Ausschlussdateien
  arbeiten strikt nach dem Fail-Closed-Prinzip (Abbruch statt ungeschütztem Upload).
- Versteckte Dateien/Ordner (`.env`, `.git`, ...), Symlinks und ausgeschlossene
  Dateien werden auch in komplett neuen Ordnern niemals ungeprüft hochgeladen.
- Neue Dateien und Ordner werden hochgeladen.
- Dateien, die in der Cloud älter sind als auf dem PC, werden durch die
  PC-Version ersetzt (als neue Revision über `-f create-new-revision -d merge`).
- Dateien, die in der Cloud neuer oder gleich alt (bzw. inhaltsgleich) sind,
  werden nicht überschrieben; verdächtige Zukunfts-Zeitstempel in Cloud-Metadaten
  werden erkannt und gemeldet.
- Es werden NIEMALS Dateien oder Ordner gelöscht, ohne dass sie durch eine
  neuere Version ersetzt werden (keine Löschbefehle, Ordner-Strategie `merge`).
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
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple


def _default_documents_dir() -> Path:
    dok = Path.home() / "Dokumente"
    docs = Path.home() / "Documents"
    if not dok.exists() and docs.exists():
        return docs
    return dok


def _default_proton_drive_bin() -> str:
    """Bevorzugt vertrauenswürdige Systempfade vor beliebigen $PATH-Einträgen."""
    for candidate in ("/usr/bin/proton-drive", "/usr/local/bin/proton-drive"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("proton-drive") or "/usr/bin/proton-drive"


PROTON_DRIVE_BIN = _default_proton_drive_bin()
REMOTE_ROOT = "/my-files"
DEFAULT_DOKUMENTE = _default_documents_dir()
DEFAULT_ZOTERO = Path.home() / "Zotero"
DEFAULT_EXCLUDE_FILE = Path(__file__).resolve().parent / "exclude.txt"
DEFAULT_LOCAL_EXCLUDE_FILE = Path(__file__).resolve().parent / "exclude.local.txt"
DEFAULT_USER_EXCLUDE_FILE = Path.home() / ".config" / "proton-sync" / "exclude.txt"

MAX_WORKERS_LIMIT = 16
DEFAULT_LIST_TIMEOUT_SEC = 60
DEFAULT_UPLOAD_TIMEOUT_SEC = 1800
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
    if name.endswith("\\"):
        return (
            False,
            "Abschließender Backslash '\\' erzeugt Pfad-Mehrdeutigkeit in proton-drive",
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
            f"proton-drive CLI nicht gefunden unter '{safe_str(path_str)}': {safe_str(exc)}",
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
class SyncAction:
    local_path: Path
    remote_parent: str
    reason: str  # "create_remote_folder", "new_folder", "new_file", "updated_file"
    details: str = ""


@dataclass
class SyncStats:
    folders_checked: int = 0
    new_folders: int = 0
    new_files: int = 0
    updated_files: int = 0
    skipped_identical: int = 0
    skipped_remote_newer_or_equal: int = 0
    ignored_loose_files: List[Path] = field(default_factory=list)
    excluded_folders: List[Tuple[Path, str]] = field(default_factory=list)
    excluded_files: List[Tuple[Path, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


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
    try:
        with os.fdopen(fd, "rb") as f:
            while chunk := f.read(1024 * 1024):
                sha1.update(chunk)
                if sha256 is not None:
                    sha256.update(chunk)
    except Exception:
        raise
    return sha1.hexdigest().lower(), (sha256.hexdigest().lower() if sha256 else None)


def compute_sha1(file_path: Path) -> str:
    digest, _ = compute_digests(file_path, need_sha256=False)
    return digest


def get_local_mtime_utc(file_path: Path) -> datetime.datetime:
    st = file_path.stat()
    return datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)


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
    `exclude_patterns` ausgeschlossen ist.

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

    expanded_target_str = os.path.expanduser(str(target_path))
    logical_target = Path(os.path.abspath(expanded_target_str))
    resolved_target = target_path.expanduser().resolve()
    target_name = target_path.name or resolved_target.name

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
            if rel != ".":
                if rel not in rel_candidates:
                    rel_candidates.append(rel)
                for bname in base_names:
                    prefixed = f"{bname}/{rel}"
                    if prefixed not in rel_candidates:
                        rel_candidates.append(prefixed)
            else:
                for bname in base_names:
                    if bname not in rel_candidates:
                        rel_candidates.append(bname)

    logical_posix = logical_target.as_posix()
    resolved_posix = resolved_target.as_posix()

    for raw_pattern in exclude_patterns:
        pattern = raw_pattern.strip().rstrip("/")
        if not pattern:
            continue

        # 1. Absoluter Pfad oder ~/... Pfad (prüft sowohl logischen als auch aufgelösten Pfad)
        if pattern.startswith("/") or pattern.startswith("~"):
            expanded_pat_logical = Path(
                os.path.abspath(os.path.expanduser(pattern))
            ).as_posix().rstrip("/")
            expanded_pat_resolved = (
                Path(pattern).expanduser().resolve().as_posix().rstrip("/")
            )
            for folder_posix in (logical_posix, resolved_posix):
                for pat_posix in (expanded_pat_logical, expanded_pat_resolved):
                    if not pat_posix:
                        continue
                    if (
                        folder_posix == pat_posix
                        or folder_posix.startswith(pat_posix + "/")
                        or fnmatch.fnmatchcase(folder_posix, pat_posix)
                    ):
                        return True, raw_pattern
            continue

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


def is_zotero_sqlite_in_use(zotero_dir: Path) -> bool:
    """
    Erkennt rein lesend (ohne `zotero.sqlite` zu verändern), ob Zotero aktuell
    auf die SQLite-Datenbank zugreift oder unbereinigte Journal-/WAL-Dateien vorliegen.
    """
    sqlite_file = zotero_dir / "zotero.sqlite"
    if not sqlite_file.exists():
        return False

    for marker in (
        "zotero.sqlite.lock",
        "zotero.sqlite-journal",
        "zotero.sqlite-wal",
        "zotero.sqlite-shm",
    ):
        if os.path.lexists(zotero_dir / marker):
            return True

    # Prüfe eigene Prozesse unter /proc/<pid>/fd auf geöffnete zotero.sqlite
    proc_root = Path("/proc")
    if proc_root.is_dir():
        try:
            target_real = str(sqlite_file.resolve())
            my_pid = os.getpid()
            for entry in os.scandir(proc_root):
                if not entry.name.isdigit() or int(entry.name) == my_pid:
                    continue
                fd_dir = Path(entry.path) / "fd"
                try:
                    for fd_entry in os.scandir(fd_dir):
                        try:
                            if os.readlink(fd_entry.path) == target_real:
                                return True
                        except OSError:
                            continue
                except OSError:
                    continue
        except OSError:
            pass

    return False


def has_excluded_descendant(
    folder_path: Path,
    exclude_patterns: Sequence[str],
    include_hidden: bool,
    base_dirs: Sequence[Path] = (),
) -> bool:
    """
    Prüft rekursiv (inkl. versteckter Einträge!), ob innerhalb von `folder_path`
    mindestens ein durch `exclude_patterns` ausgeschlossenes Element liegt.
    Bei Lesefehlern wird sicherheitshalber `True` (Fail-Closed) zurückgegeben.
    """
    if not exclude_patterns:
        return False

    visited_inodes: Set[Tuple[int, int]] = set()
    stack: List[Path] = [folder_path]
    while stack:
        current = stack.pop()
        try:
            st = os.lstat(current)
            if stat.S_ISLNK(st.st_mode):
                continue
            inode_key = (st.st_dev, st.st_ino)
            if inode_key in visited_inodes:
                return True
            visited_inodes.add(inode_key)

            for child in current.iterdir():
                if child.is_symlink():
                    continue
                # Wichtig: Ausschlussprüfung VOR dem Dotfile-Filter ausführen,
                # damit z. B. `.git` in exclude.txt niemals übersehen wird!
                excluded, _ = is_excluded_path(child, exclude_patterns, base_dirs)
                if excluded:
                    return True
                if child.name.startswith(".") and not include_hidden:
                    continue
                if child.is_dir():
                    stack.append(child)
        except OSError:
            return True
    return False


def requires_split_folder_upload(
    folder_path: Path,
    exclude_patterns: Sequence[str],
    include_hidden: bool,
    base_dirs: Sequence[Path] = (),
    locked_skip_files: Set[Path] = frozenset(),
) -> bool:
    """
    Entscheidet, ob ein neuer Ordner NICHT als monolithisches Komplettpaket (`new_folder`)
    an `proton-drive` übergeben werden darf, sondern in Python einzeln aufgeteilt werden muss.

    Gibt `True` zurück, sobald im Teilbaum mindestens eines der folgenden Elemente existiert:
    - ein ausgeschlossener Unterordner oder eine ausgeschlossene Datei
    - eine versteckte Datei / ein versteckter Ordner (wenn `include_hidden=False`),
      damit `.env`, `.git` etc. nicht durch `proton-drive` mit hochgeladen werden
    - ein Symlink (Datei oder Ordner)
    - eine Spezialdatei (FIFO, Socket, Device), ein unsicherer Knotenname,
      eine gesperrte Datenbankdatei (`locked_skip_files`) oder ein Dateisystem-Zyklus/Lesefehler.
    """
    visited_inodes: Set[Tuple[int, int]] = set()
    stack: List[Path] = [folder_path]

    while stack:
        current = stack.pop()
        try:
            st = os.lstat(current)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                return True
            inode_key = (st.st_dev, st.st_ino)
            if inode_key in visited_inodes:
                return True
            visited_inodes.add(inode_key)

            for child in current.iterdir():
                if child.is_symlink():
                    return True
                if child.name.startswith(".") and not include_hidden:
                    return True
                ok_name, _ = is_safe_node_name(child.name)
                if not ok_name:
                    return True
                if locked_skip_files and child.resolve() in locked_skip_files:
                    return True
                excluded, _ = is_excluded_path(child, exclude_patterns, base_dirs)
                if excluded:
                    return True

                child_st = os.lstat(child)
                if stat.S_ISDIR(child_st.st_mode):
                    stack.append(child)
                elif not stat.S_ISREG(child_st.st_mode):
                    return True
        except OSError:
            return True

    return False


def plan_new_folder_with_exclusions(
    local_dir: Path,
    remote_parent: str,
    include_hidden: bool,
    exclude_patterns: Sequence[str],
    base_dirs: Sequence[Path],
    stats: SyncStats,
    locked_skip_files: Set[Path] = frozenset(),
    _visited_inodes: Optional[Set[Tuple[int, int]]] = None,
) -> List[SyncAction]:
    """
    Plant den Upload eines in der Cloud noch nicht existierenden Ordners `local_dir`.
    - Nur wenn der gesamte Teilbaum frei von Ausschlüssen, versteckten Dateien
      (bei `not include_hidden`), Symlinks und gesperrten Dateien ist:
      1 kompletter Ordner-Upload (`new_folder`).
    - Andernfalls: Legt den Elternordner in der Cloud an (`create_remote_folder`)
      und plant ausschließlich geprüfte, erlaubte Dateien und Unterordner ein.
    """
    ok_name, reason = is_safe_node_name(local_dir.name)
    if not ok_name:
        stats.errors.append(
            f"Überspringe Ordner mit unsicherem Namen {safe_str(local_dir)}: {reason}"
        )
        return []

    visited = _visited_inodes if _visited_inodes is not None else set()
    try:
        dir_st = os.lstat(local_dir)
        if stat.S_ISLNK(dir_st.st_mode) or not stat.S_ISDIR(dir_st.st_mode):
            return []
        inode_key = (dir_st.st_dev, dir_st.st_ino)
        if inode_key in visited:
            stats.warnings.append(
                f"Dateisystem-Zyklus erkannt, überspringe Ordner: {safe_str(local_dir)}"
            )
            return []
        visited.add(inode_key)
    except OSError as exc:
        stats.errors.append(
            f"Konnte lokalen Ordner nicht prüfen {safe_str(local_dir)}: {safe_str(exc)}"
        )
        return []

    if not requires_split_folder_upload(
        local_dir,
        exclude_patterns,
        include_hidden,
        base_dirs,
        locked_skip_files=locked_skip_files,
    ):
        stats.new_folders += 1
        return [
            SyncAction(
                local_path=local_dir,
                remote_parent=remote_parent,
                reason="new_folder",
                details="Neuer Ordner (geprüfter Inhalt)",
            )
        ]

    try:
        remote_this = join_remote_path(remote_parent, local_dir.name)
    except ValueError as exc:
        stats.errors.append(str(exc))
        return []

    actions: List[SyncAction] = [
        SyncAction(
            local_path=local_dir,
            remote_parent=remote_parent,
            reason="create_remote_folder",
            details="Ordner in Cloud anlegen (gefilterter Einzel-Upload)",
        )
    ]
    stats.new_folders += 1

    try:
        children = sorted(local_dir.iterdir(), key=lambda p: p.name.lower())
    except OSError as exc:
        stats.errors.append(
            f"Konnte lokalen Ordner nicht lesen {safe_str(local_dir)}: {safe_str(exc)}"
        )
        return actions

    for child in children:
        if child.is_symlink():
            continue
        if child.name.startswith(".") and not include_hidden:
            continue

        ok_child, child_reason = is_safe_node_name(child.name)
        if not ok_child:
            stats.errors.append(
                f"Überspringe Element mit unsicherem Namen {safe_str(child)}: {child_reason}"
            )
            continue

        try:
            child_st = os.lstat(child)
        except OSError as exc:
            stats.errors.append(
                f"Konnte Element nicht prüfen {safe_str(child)}: {safe_str(exc)}"
            )
            continue

        if stat.S_ISDIR(child_st.st_mode):
            excluded, matched = is_excluded_path(child, exclude_patterns, base_dirs)
            if excluded:
                stats.excluded_folders.append((child, matched or ""))
                continue
            actions.extend(
                plan_new_folder_with_exclusions(
                    local_dir=child,
                    remote_parent=remote_this,
                    include_hidden=include_hidden,
                    exclude_patterns=exclude_patterns,
                    base_dirs=base_dirs,
                    stats=stats,
                    locked_skip_files=locked_skip_files,
                    _visited_inodes=visited,
                )
            )
        elif stat.S_ISREG(child_st.st_mode):
            excluded, matched = is_excluded_path(child, exclude_patterns, base_dirs)
            if excluded:
                stats.excluded_files.append((child, matched or ""))
                continue
            if locked_skip_files and child.resolve() in locked_skip_files:
                continue
            stats.new_files += 1
            actions.append(
                SyncAction(
                    local_path=child,
                    remote_parent=remote_this,
                    reason="new_file",
                    details="Neue Datei",
                )
            )

    return actions


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
) -> List[Tuple[Path, str, str]]:
    """
    Bestimmt alle zu synchronisierenden Top-Level-Ordner unter Berücksichtigung
    der Ausschlussliste `exclude_patterns`.
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
            if entry.name.startswith(".") and not include_hidden:
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir():
                ok_name, reason = is_safe_node_name(entry.name)
                if not ok_name:
                    stats.errors.append(
                        f"Überspringe Top-Level-Ordner {safe_str(entry)}: {reason}"
                    )
                    continue
                excluded, matched = is_excluded_path(entry, exclude_patterns, base_dirs)
                if excluded:
                    stats.excluded_folders.append((entry, matched or ""))
                    continue
                targets.append((entry, REMOTE_ROOT, entry.name))
            elif entry.is_file():
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
    include_hidden: bool,
    proton_bin: str,
    executor: concurrent.futures.ThreadPoolExecutor,
    stats: SyncStats,
    exclude_patterns: Sequence[str] = (),
    base_dirs: Sequence[Path] = (),
    mtime_tolerance_sec: float = 1.0,
    locked_skip_files: Set[Path] = frozenset(),
    list_timeout_sec: int = DEFAULT_LIST_TIMEOUT_SEC,
) -> List[SyncAction]:
    """
    Durchläuft `local_dir` ebenenweise (BFS) und nutzt parallele `filesystem list -j`
    Abfragen für bereits in der Cloud vorhandene Unterordner.
    Ausgeschlossene Ordner UND Dateien (`exclude_patterns`) werden übersprungen.
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
                if child.is_symlink():
                    continue
                if child.name.startswith(".") and not include_hidden:
                    continue

                ok_name, name_reason = is_safe_node_name(child.name)
                if not ok_name:
                    stats.errors.append(
                        f"Überspringe Element mit unsicherem Namen {safe_str(child)}: {name_reason}"
                    )
                    continue

                try:
                    child_st = os.lstat(child)
                except OSError as exc:
                    stats.errors.append(
                        f"Konnte Element nicht prüfen {safe_str(child)}: {safe_str(exc)}"
                    )
                    continue

                remote_node = remote_entries.get(child.name)

                if stat.S_ISDIR(child_st.st_mode):
                    excluded, matched = is_excluded_path(
                        child, exclude_patterns, base_dirs
                    )
                    if excluded:
                        stats.excluded_folders.append((child, matched or ""))
                        continue

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
                                include_hidden=include_hidden,
                                exclude_patterns=exclude_patterns,
                                base_dirs=base_dirs,
                                stats=stats,
                                locked_skip_files=locked_skip_files,
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

                elif stat.S_ISREG(child_st.st_mode):
                    excluded, matched = is_excluded_path(
                        child, exclude_patterns, base_dirs
                    )
                    if excluded:
                        stats.excluded_files.append((child, matched or ""))
                        continue

                    if locked_skip_files and child.resolve() in locked_skip_files:
                        continue

                    if remote_node is None:
                        stats.new_files += 1
                        actions.append(
                            SyncAction(
                                local_path=child,
                                remote_parent=r_path,
                                reason="new_file",
                                details="Neue Datei",
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
                                )
                            )
                        else:
                            if category == "identical":
                                stats.skipped_identical += 1
                            else:
                                stats.skipped_remote_newer_or_equal += 1

        current_level = next_level

    return actions


def verify_action_before_execution(
    action: SyncAction,
    allowed_roots: Sequence[Path],
    exclude_patterns: Sequence[str] = (),
    include_hidden: bool = False,
    base_dirs: Sequence[Path] = (),
    locked_skip_files: Set[Path] = frozenset(),
) -> Tuple[bool, str]:
    """
    TOCTOU-Schutz unmittelbar vor dem Aufruf von `proton-drive`:
    Prüft per `lstat`, dass weder das Ziel selbst noch ein Zwischenordner seit
    dem Scan durch einen Symlink ersetzt wurde und bei `new_folder` keine
    versteckten/ausgeschlossenen Dateien nachträglich abgelegt wurden.
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

    ok_name, name_reason = is_safe_node_name(local_path.name)
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
        return (
            False,
            f"TOCTOU-Schutz: {safe_str(local_path)} wurde durch einen Symlink ersetzt!",
        )

    expect_dir = action.reason in ("create_remote_folder", "new_folder")
    if expect_dir and not stat.S_ISDIR(lst.st_mode):
        return (
            False,
            f"TOCTOU-Schutz: {safe_str(local_path)} ist kein Verzeichnis mehr!",
        )
    if not expect_dir and not stat.S_ISREG(lst.st_mode):
        return (
            False,
            f"TOCTOU-Schutz: {safe_str(local_path)} ist keine reguläre Datei mehr!",
        )

    # Prüfe alle Elternverzeichnisse bis zur erlaubten Wurzel auf nachträgliche Symlinks
    if allowed_roots:
        matched_root: Optional[Path] = None
        for root in allowed_roots:
            try:
                local_path.relative_to(root)
                matched_root = root
                break
            except ValueError:
                continue
        if matched_root is None:
            return (
                False,
                f"Pfad liegt außerhalb der erlaubten Quellordner: {safe_str(local_path)}",
            )

        cur = local_path.parent
        while len(cur.parts) >= len(matched_root.parts):
            try:
                cur_st = os.lstat(cur)
            except OSError as exc:
                return (
                    False,
                    f"Elternordner nicht prüfbar {safe_str(cur)}: {safe_str(exc)}",
                )
            if stat.S_ISLNK(cur_st.st_mode):
                return (
                    False,
                    f"TOCTOU-Schutz: Elternordner {safe_str(cur)} wurde durch Symlink ersetzt!",
                )
            if cur == matched_root:
                break
            cur = cur.parent

    if action.reason == "new_folder":
        if requires_split_folder_upload(
            local_path,
            exclude_patterns=exclude_patterns,
            include_hidden=include_hidden,
            base_dirs=base_dirs,
            locked_skip_files=locked_skip_files,
        ):
            return (
                False,
                f"TOCTOU-Schutz: Neuer Ordner {safe_str(local_path)} enthält inzwischen "
                "zu filternde Elemente (bitte Synchronisation erneut starten).",
            )

    return True, ""


def execute_upload_batches(
    actions: List[SyncAction],
    proton_bin: str,
    conflict_strategy: str = "create-new-revision",
    batch_size: int = 50,
    dry_run: bool = False,
    verbose: bool = False,
    allowed_roots: Sequence[Path] = (),
    exclude_patterns: Sequence[str] = (),
    include_hidden: bool = False,
    base_dirs: Sequence[Path] = (),
    locked_skip_files: Set[Path] = frozenset(),
    upload_timeout_sec: int = DEFAULT_UPLOAD_TIMEOUT_SEC,
) -> List[str]:
    """
    Führt zuerst ggf. notwendige Remote-Ordner-Erstellungen (`create_remote_folder`)
    aus und gruppiert anschließend alle Datei-/Ordner-Uploads nach ihrem Zielordner
    (`remote_parent`) via:
    `proton-drive filesystem upload -f <conflict_strategy> -d merge -- <pfade...> <remote_parent>`
    """
    errors: List[str] = []
    if not actions:
        return errors

    mkdir_actions = [a for a in actions if a.reason == "create_remote_folder"]
    upload_actions = [a for a in actions if a.reason != "create_remote_folder"]

    for a in mkdir_actions:
        try:
            target_preview = join_remote_path(a.remote_parent, a.local_path.name)
        except ValueError as exc:
            errors.append(str(exc))
            continue

        if dry_run or verbose:
            print(
                f"  [ORDNER ANLEGEN] {safe_str(a.local_path)} -> "
                f"{safe_str(target_preview)} ({safe_str(a.details)})"
            )
        if dry_run:
            continue

        ok_verify, verify_err = verify_action_before_execution(
            a,
            allowed_roots=allowed_roots,
            exclude_patterns=exclude_patterns,
            include_hidden=include_hidden,
            base_dirs=base_dirs,
            locked_skip_files=locked_skip_files,
        )
        if not ok_verify:
            errors.append(verify_err)
            continue

        cmd = [
            proton_bin,
            "filesystem",
            "create-folder",
            "--",
            a.remote_parent,
            a.local_path.name,
        ]
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=upload_timeout_sec,
            )
            if proc.returncode != 0:
                errors.append(
                    f"Ordner-Erstellung fehlgeschlagen (Exit-Code {proc.returncode}) "
                    f"für {safe_str(a.local_path.name)} in {safe_str(a.remote_parent)}"
                )
        except subprocess.TimeoutExpired:
            errors.append(
                f"Zeitüberschreitung ({upload_timeout_sec}s) beim Anlegen von "
                f"{safe_str(a.local_path.name)} in {safe_str(a.remote_parent)}"
            )
        except OSError as exc:
            errors.append(
                f"Prozessfehler beim Anlegen von {safe_str(a.local_path.name)}: {safe_str(exc)}"
            )

    grouped: Dict[str, List[SyncAction]] = {}
    for act in upload_actions:
        grouped.setdefault(act.remote_parent, []).append(act)

    for remote_parent, group in grouped.items():
        for i in range(0, len(group), batch_size):
            raw_batch = group[i : i + batch_size]

            if dry_run or verbose:
                for a in raw_batch:
                    tag = {
                        "new_folder": "[NEUER ORDNER]",
                        "new_file": "[NEUE DATEI]  ",
                        "updated_file": "[AKTUALISIERT]",
                    }.get(a.reason, "[UPLOAD]")
                    print(
                        f"  {tag} {safe_str(a.local_path)} -> "
                        f"{safe_str(a.remote_parent)} ({safe_str(a.details)})"
                    )

            if dry_run:
                continue

            verified_batch: List[SyncAction] = []
            for a in raw_batch:
                ok_verify, verify_err = verify_action_before_execution(
                    a,
                    allowed_roots=allowed_roots,
                    exclude_patterns=exclude_patterns,
                    include_hidden=include_hidden,
                    base_dirs=base_dirs,
                    locked_skip_files=locked_skip_files,
                )
                if not ok_verify:
                    errors.append(verify_err)
                else:
                    verified_batch.append(a)

            if not verified_batch:
                continue

            local_paths = [str(a.local_path) for a in verified_batch]
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

            print(
                f"-> Lade {len(verified_batch)} Element(e) hoch nach {safe_str(remote_parent)} ..."
            )
            try:
                proc = subprocess.run(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=upload_timeout_sec,
                )
                if proc.returncode != 0:
                    errors.append(
                        f"Upload fehlgeschlagen (Exit-Code {proc.returncode}) "
                        f"für Ziel {safe_str(remote_parent)}"
                    )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"Zeitüberschreitung ({upload_timeout_sec}s) beim Upload nach "
                    f"{safe_str(remote_parent)}"
                )
            except OSError as exc:
                errors.append(
                    f"Prozessfehler beim Upload nach {safe_str(remote_parent)}: {safe_str(exc)}"
                )

    return errors


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
            "Schließt bestimmte Ordner oder Dateien von der Synchronisation aus. "
            "Mehrfach nutzbar oder kommagetrennt (z. B. `-x Videos -x *.kdbx` "
            "oder `--exclude Videos,node_modules`; `\\,` für Komma im Namen)."
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
        default=DEFAULT_UPLOAD_TIMEOUT_SEC,
        help=f"Maximale Laufzeit pro Upload-Batch in Sekunden (Standard: {DEFAULT_UPLOAD_TIMEOUT_SEC}).",
    )
    parser.add_argument(
        "--file-conflict-strategy",
        choices=["create-new-revision", "replace"],
        default="create-new-revision",
        help=(
            "Konfliktstrategie für ältere Cloud-Dateien: "
            "'create-new-revision' (Standard, legt neue Dateiversion an ohne Löschen) "
            "oder 'replace'."
        ),
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

    raw_dok = args.dokumente.expanduser()
    raw_zot = args.zotero.expanduser()
    resolved_dok = raw_dok.resolve()
    resolved_zot = raw_zot.resolve()
    base_dirs = [raw_dok, raw_zot]
    allowed_roots = [resolved_dok, resolved_zot]

    use_lock = not args.no_lock and not args.dry_run
    try:
        lock_ctx = SingleInstanceLock(enabled=use_lock)
    except Exception as exc:
        print(f"FEHLER bei Lock-Initialisierung: {safe_str(exc)}", file=sys.stderr)
        return 3

    try:
        with lock_ctx:
            return _run_sync_session(
                args=args,
                proton_bin=resolved_proton_bin,
                raw_dok=raw_dok,
                raw_zot=raw_zot,
                resolved_dok=resolved_dok,
                resolved_zot=resolved_zot,
                base_dirs=base_dirs,
                allowed_roots=allowed_roots,
                exclude_patterns=exclude_patterns,
            )
    except RuntimeError as exc:
        print(f"FEHLER: {safe_str(exc)}", file=sys.stderr)
        return 3


def _run_sync_session(
    *,
    args: argparse.Namespace,
    proton_bin: str,
    raw_dok: Path,
    raw_zot: Path,
    resolved_dok: Path,
    resolved_zot: Path,
    base_dirs: Sequence[Path],
    allowed_roots: Sequence[Path],
    exclude_patterns: Sequence[str],
) -> int:
    stats = SyncStats()
    targets = collect_sync_targets(
        dokumente_dir=raw_dok,
        zotero_dir=raw_zot,
        include_hidden=args.include_hidden,
        stats=stats,
        exclude_patterns=exclude_patterns,
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
    if (
        not args.allow_live_zotero
        and any(t[0] == resolved_zot for t in targets)
        and is_zotero_sqlite_in_use(resolved_zot)
    ):
        for side_name in ZOTERO_SQLITE_SIDE_FILES:
            candidate = resolved_zot / side_name
            if candidate.exists():
                locked_skip_files.add(candidate.resolve())
        stats.warnings.append(
            f"Zotero scheint geöffnet zu sein oder hat offene Journal-/WAL-Dateien in "
            f"{safe_str(resolved_zot)} – überspringe zotero.sqlite*, um korrupte Backups "
            "zu verhindern (--allow-live-zotero zum Erzwingen)."
        )

    workers = min(max(1, args.workers), MAX_WORKERS_LIMIT)
    upload_timeout = max(30, args.timeout)
    list_timeout = min(DEFAULT_LIST_TIMEOUT_SEC, upload_timeout)

    mode_label = "TROCKENLAUF (DRY-RUN)" if args.dry_run else "LIVE-SYNCHRONISATION"
    print(f"=== Proton Drive Synchronisation ({mode_label}) ===")
    print(
        f"Dokumente-Quelle : {safe_str(resolved_dok)} (nur Unterordner, keine losen Dateien)"
    )
    print(f"Zotero-Quelle    : {safe_str(resolved_zot)}")
    print(f"Cloud-Ziel       : {REMOTE_ROOT}")
    print(f"Proton-Binary    : {safe_str(proton_bin)}")
    print(
        f"Konflikt-Modus   : -f {args.file_conflict_strategy} -d merge (keine Löschungen!)"
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
        timeout_sec=list_timeout,
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
                folder_actions = plan_new_folder_with_exclusions(
                    local_dir=local_folder,
                    remote_parent=remote_parent,
                    include_hidden=args.include_hidden,
                    exclude_patterns=exclude_patterns,
                    base_dirs=base_dirs,
                    stats=stats,
                    locked_skip_files=locked_skip_files,
                )
                all_actions.extend(folder_actions)
            else:
                print(
                    f"[*] Vergleiche Ordner: {safe_str(local_folder)} <-> {safe_str(remote_folder_path)} ..."
                )
                folder_actions = plan_directory_sync(
                    local_dir=local_folder,
                    remote_dir_path=remote_folder_path,
                    include_hidden=args.include_hidden,
                    proton_bin=proton_bin,
                    executor=executor,
                    stats=stats,
                    exclude_patterns=exclude_patterns,
                    base_dirs=base_dirs,
                    locked_skip_files=locked_skip_files,
                    list_timeout_sec=list_timeout,
                )
                all_actions.extend(folder_actions)

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
            exclude_patterns=exclude_patterns,
            include_hidden=args.include_hidden,
            base_dirs=base_dirs,
            locked_skip_files=locked_skip_files,
            upload_timeout_sec=upload_timeout,
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
