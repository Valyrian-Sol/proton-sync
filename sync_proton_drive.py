#!/usr/bin/python3 -I
"""
Proton Drive Sync-Script (Einweg-Synchronisation PC -> Proton Drive)

Synchronisiert standardmäßig (über `sources.txt`, `sources.local.txt`,
`~/.config/proton-sync/sources.txt` sowie `--add-source` / `--remove-source` /
`--source` / `--skip-source` frei konfigurierbar):
1. Alle Unterordner in ~/Dokumente -> /my-files/<Unterordner>
   (Modus `subfolders`: lose Dateien direkt in ~/Dokumente werden ignoriert!)
2. Den Ordner ~/Zotero -> /my-files/Zotero
   (Modus `folder`: kompletter Ordner inkl. Unterordner und loser Dateien)
3. Optional weitere Standardordner (z. B. `~/.config` -> `/my-files/.config`)

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
DEFAULT_SOURCES_FILE = Path(__file__).resolve().parent / "sources.txt"
DEFAULT_LOCAL_SOURCES_FILE = Path(__file__).resolve().parent / "sources.local.txt"
DEFAULT_USER_SOURCES_FILE = Path.home() / ".config" / "proton-sync" / "sources.txt"
VALID_SOURCE_MODES = ("folder", "subfolders")

STAGING_PREFIX = ".proton-sync-stage-"
MAX_WORKERS_LIMIT = 16
DEFAULT_LIST_TIMEOUT_SEC = 60
FUTURE_MTIME_SKEW_TOLERANCE = datetime.timedelta(minutes=5)
MAX_CONFIG_FILE_BYTES = 1024 * 1024
MAX_STREAM_LINE_BYTES = 65536

FORBIDDEN_TREE_SOURCE_DIRS: Tuple[Path, ...] = (
    Path("/proc"),
    Path("/sys"),
    Path("/dev"),
)
FORBIDDEN_EXACT_SOURCE_DIRS: FrozenSet[Path] = frozenset(
    {
        Path("/"),
        Path("/etc"),
        Path("/boot"),
        Path("/usr"),
        Path("/var"),
        Path("/run"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
    }
)

# Eingebaute Standard-Ausschlüsse für hochsensible Geheimnisse, Tresore, Tokens und
# Browser-/Proton-Profile (insbesondere wichtig beim Synchronisieren von ~/.config).
# Mit `--allow-sensitive` bei Bedarf explizit übersteuerbar.
SENSITIVE_DEFAULT_EXCLUDES: Tuple[str, ...] = (
    "*.kdbx",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "*.env",
    "~/.ssh",
    "~/.gnupg",
    "~/.aws",
    "~/.kube",
    "~/.local/share/keyrings",
    "~/.local/share/proton*",
    "~/.local/state/proton*",
    "~/.config/proton*",
    "~/.config/Proton*",
    "~/.config/google-chrome*",
    "~/.config/chromium*",
    "~/.config/BraveSoftware",
    "~/.config/vivaldi*",
    "~/.config/microsoft-edge*",
    "~/.config/opera*",
    "~/.config/Bitwarden*",
    "~/.config/1Password*",
    "~/.config/keepassxc",
    "~/.config/keyrings",
    "~/.config/gh",
    "~/.config/glab-cli",
    "~/.config/hub",
    "~/.config/rclone",
    "~/.config/gcloud",
    "~/.config/aws",
    "~/.config/azure",
    "~/.config/kube",
    "~/.config/op",
    "~/.config/sops",
    "~/.config/age",
    "~/.config/gnupg",
    "~/.config/syncthing",
    "~/.config/Signal*",
    "~/.config/Element*",
    "~/.config/TelegramDesktop",
    "~/.config/discord*",
    "~/.config/Slack*",
)

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


def _verify_secure_directory_chain(
    dir_path: Path, *, reject_leaf_symlink: bool = True
) -> Optional[str]:
    """
    Prüft, ob `dir_path` und sämtliche übergeordneten Verzeichnisse bis `/`
    einem vertrauenswürdigen Benutzer (root oder aktuellem User) gehören und
    nicht ungeschützt world-writable (ohne Sticky-Bit) sind.
    """
    try:
        lst = os.lstat(dir_path)
    except OSError as exc:
        return f"Verzeichnis nicht prüfbar {safe_str(dir_path)}: {safe_str(exc)}"

    if reject_leaf_symlink and stat.S_ISLNK(lst.st_mode):
        return f"Verzeichnis darf kein Symlink sein: {safe_str(dir_path)}"
    if not stat.S_ISDIR(lst.st_mode) and not (
        not reject_leaf_symlink and stat.S_ISLNK(lst.st_mode)
    ):
        return f"Kein Verzeichnis: {safe_str(dir_path)}"

    allowed_uids = {0, os.geteuid()}
    resolved = Path(os.path.realpath(dir_path))
    cur = resolved
    while True:
        try:
            st = os.stat(cur)
        except OSError as exc:
            return f"Verzeichnis nicht prüfbar {safe_str(cur)}: {safe_str(exc)}"
        if not stat.S_ISDIR(st.st_mode):
            return f"Elternelement ist kein Verzeichnis: {safe_str(cur)}"
        if st.st_uid not in allowed_uids:
            return f"Unsicherer Eigentümer (UID {st.st_uid}) für Verzeichnis: {safe_str(cur)}"
        if (st.st_mode & stat.S_IWOTH) and not (st.st_mode & stat.S_ISVTX):
            return f"Verzeichnis ist world-writable ohne Sticky-Bit: {safe_str(cur)}"
        if cur == cur.parent:
            break
        cur = cur.parent
    return None


def _sanitized_cli_env() -> Dict[str, str]:
    """
    Erzeugt eine bereinigte Prozessumgebung für `proton-drive`:
    Entfernt Loader-/Runtime-Injection-Variablen (`LD_*`, `DOTNET_*`, `SSLKEYLOGFILE`,
    `OPENSSL_CONF`, `PYTHON*` usw.) und setzt einen vertrauenswürdigen `PATH`.
    """
    blocked_exact = frozenset(
        {
            "SSLKEYLOGFILE",
            "OPENSSL_CONF",
            "OPENSSL_ENGINES",
            "OPENSSL_MODULES",
            "GCONV_PATH",
            "GETCONF_DIR",
            "HOSTALIASES",
            "LOCALDOMAIN",
            "RES_OPTIONS",
        }
    )
    blocked_prefixes = (
        "LD_",
        "DYLD_",
        "DOTNET_",
        "CORECLR_",
        "COR_",
        "COMPlus_",
        "PYTHON",
    )
    env: Dict[str, str] = {}
    for key, val in os.environ.items():
        if key in blocked_exact or any(key.startswith(p) for p in blocked_prefixes):
            continue
        env[key] = val
    env["PATH"] = "/usr/bin:/bin"
    return env


def validate_proton_binary(path_str: str) -> Tuple[bool, Optional[str], str]:
    """
    Prüft, ob das `proton-drive` Binary existiert, ausführbar ist, einem
    vertrauenswürdigen Benutzer (root oder aktuellem User) gehört und weder
    selbst noch in der Verzeichniskette bis `/` ungeschützt world-writable ist.
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
    chain_err = _verify_secure_directory_chain(
        Path(parent_dir), reject_leaf_symlink=False
    )
    if chain_err:
        return False, None, chain_err

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
                    and _verify_secure_directory_chain(
                        Path(xdg_runtime), reject_leaf_symlink=True
                    )
                    is None
                ):
                    return Path(xdg_runtime)
            except OSError:
                pass

        fallback = Path.home() / ".cache" / "proton-sync"
        ancestor = fallback
        while not os.path.lexists(ancestor) and ancestor != ancestor.parent:
            ancestor = ancestor.parent
        if os.path.lexists(ancestor):
            chain_err = _verify_secure_directory_chain(
                ancestor, reject_leaf_symlink=False
            )
            if chain_err:
                raise PermissionError(f"Unsicheres Lock-Verzeichnis: {chain_err}")
        fallback.mkdir(parents=True, mode=0o700, exist_ok=True)
        st = os.lstat(fallback)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
            raise PermissionError(
                f"Unsicheres Lock-Verzeichnis: {safe_str(fallback)}"
            )
        if st.st_mode & 0o077:
            os.chmod(fallback, 0o700)
        chain_err = _verify_secure_directory_chain(fallback, reject_leaf_symlink=True)
        if chain_err:
            raise PermissionError(f"Unsicheres Lock-Verzeichnis: {chain_err}")
        return fallback

    def __enter__(self) -> "SingleInstanceLock":
        if not self.enabled:
            return self
        lock_dir = self._select_lock_dir()
        self.lock_path = lock_dir / "proton-sync.lock"
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            fd = os.open(str(self.lock_path), flags, 0o600)
        except OSError as exc:
            raise PermissionError(
                f"Lock-Datei konnte nicht sicher geöffnet werden ({safe_str(self.lock_path)}): {safe_str(exc)}"
            ) from exc

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                raise PermissionError(
                    f"Unsichere Lock-Datei (keine eigene reguläre Datei): {safe_str(self.lock_path)}"
                )
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(
                    f"Es läuft bereits eine andere Instanz von proton-sync (Lock aktiv: {safe_str(self.lock_path)})."
                ) from exc
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        self.fd = fd
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


@dataclass(frozen=True)
class SyncSource:
    path: Path
    mode: str = "folder"  # "folder" (kompletter Ordner inkl. loser Dateien) | "subfolders" (nur Unterordner)
    origin: str = "default"


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
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(str(file_path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"Keine reguläre Datei: {safe_str(file_path)}")
        with os.fdopen(fd, "rb") as f:
            fd = -1  # os.fdopen übernimmt den Deskriptor
            while chunk := f.read(1024 * 1024):
                sha1.update(chunk)
                if sha256 is not None:
                    sha256.update(chunk)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
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


def _open_and_read_config_text(
    file_path: Path, required: bool, label: str = "Konfigurationsdatei"
) -> Optional[str]:
    """
    Öffnet und liest eine Konfigurationsdatei Atomar/TOCTOU-sicher (ohne Symlinks,
    ohne FIFOs, mit Eigentümer-/Rechte-/Größenprüfung über `fstat`).
    """
    expanded = file_path.expanduser()
    try:
        lst = os.lstat(expanded)
    except FileNotFoundError:
        if required:
            raise FileNotFoundError(
                f"Angegebene {label} existiert nicht: {safe_str(expanded)}"
            )
        return None

    if stat.S_ISLNK(lst.st_mode):
        raise PermissionError(f"{label} darf kein Symlink sein: {safe_str(expanded)}")
    if stat.S_ISDIR(lst.st_mode):
        raise IsADirectoryError(
            f"{label} ist keine reguläre Datei: {safe_str(expanded)}"
        )
    if not stat.S_ISREG(lst.st_mode):
        raise PermissionError(
            f"{label} ist keine reguläre Datei: {safe_str(expanded)}"
        )

    chain_err = _verify_secure_directory_chain(
        expanded.parent, reject_leaf_symlink=False
    )
    if chain_err:
        raise PermissionError(f"Unsicheres Verzeichnis für {label}: {chain_err}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(str(expanded), flags)
    except OSError as exc:
        if exc.errno == getattr(os.errno if hasattr(os, "errno") else None, "ELOOP", 40) or exc.errno == 40:
            raise PermissionError(
                f"{label} darf kein Symlink sein: {safe_str(expanded)}"
            ) from exc
        raise

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(
                f"{label} ist keine reguläre Datei: {safe_str(expanded)}"
            )
        allowed_uids = {0, os.geteuid()}
        if st.st_uid not in allowed_uids:
            raise PermissionError(
                f"Unsicherer Eigentümer (UID {st.st_uid}) für {label}: {safe_str(expanded)}"
            )
        if st.st_mode & stat.S_IWOTH:
            raise PermissionError(
                f"Unsichere Dateirechte (world-writable) für {label}: {safe_str(expanded)}"
            )
        if (st.st_mode & stat.S_IWGRP) and st.st_gid not in {0, os.getegid()}:
            raise PermissionError(
                f"Unsichere Gruppenrechte (group-writable für fremde Gruppe {st.st_gid}) für {label}: {safe_str(expanded)}"
            )
        if st.st_size > MAX_CONFIG_FILE_BYTES:
            raise ValueError(
                f"{label} überschreitet Maximalgröße ({MAX_CONFIG_FILE_BYTES} Bytes): {safe_str(expanded)}"
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw_bytes = handle.read(MAX_CONFIG_FILE_BYTES + 1)
        if len(raw_bytes) > MAX_CONFIG_FILE_BYTES:
            raise ValueError(
                f"{label} überschreitet Maximalgröße ({MAX_CONFIG_FILE_BYTES} Bytes): {safe_str(expanded)}"
            )
        return raw_bytes.decode("utf-8")
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_config_lines_strict(
    file_path: Path, required: bool, label: str = "Konfigurationsdatei"
) -> List[str]:
    """
    Liest eine Konfigurationsdatei (Ausschluss- oder Quellpfaddatei) nach dem Fail-Closed-Prinzip:
    - Fehlt eine optionale Standarddatei komplett, wird `[]` zurückgegeben.
    - Fehlt eine explizit angeforderte Datei (`required=True`) oder ist eine vorhandene
      Datei ein Symlink, ein Verzeichnis, zu groß oder unsicher berechtigt, wird ein Fehler ausgelöst.
    """
    content = _open_and_read_config_text(file_path, required=required, label=label)
    if content is None:
        return []
    lines: List[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _read_exclude_file_strict(file_path: Path, required: bool) -> List[str]:
    """Liest eine Ausschlussdatei nach dem Fail-Closed-Prinzip."""
    return _read_config_lines_strict(file_path, required=required, label="Ausschlussdatei")


def load_exclude_patterns(
    cli_excludes: Optional[Sequence[str]] = None,
    exclude_file: Optional[Path] = DEFAULT_EXCLUDE_FILE,
    default_excludes: Optional[Sequence[str]] = None,
    *,
    require_exclude_file: bool = False,
    extra_exclude_files: Sequence[Path] = (),
    include_sensitive_defaults: bool = False,
) -> List[str]:
    """
    Lädt und kombiniert alle Ordner-/Datei-Ausschlussmuster aus:
    1. `default_excludes` (bzw. `DEFAULT_EXCLUDED_FOLDERS`) und optional `SENSITIVE_DEFAULT_EXCLUDES`
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
    if include_sensitive_defaults:
        base_list.extend(SENSITIVE_DEFAULT_EXCLUDES)
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
                        or fnmatch.fnmatchcase(folder_posix, pat_posix + "/*")
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
                or fnmatch.fnmatchcase(rel, pattern + "/*")
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
# Konfigurierbare Standardpfade (Quellen)
# --------------------------------------------------------------------------------------


def _normalize_source_variants(path: Path) -> Set[str]:
    """Liefert logische und aufgelöste Pfadvarianten zum robusten Abgleich."""
    expanded_str = os.path.expanduser(str(path))
    logical = os.path.abspath(expanded_str)
    resolved = str(Path(expanded_str).resolve())
    return {logical, resolved}


def _sources_match(path_a: Path, path_b: Path) -> bool:
    return bool(_normalize_source_variants(path_a) & _normalize_source_variants(path_b))


def _validate_resolved_source_dir(
    resolved_src: Path, raw_display: object
) -> Optional[str]:
    """Verweigert `/` sowie kritische Systemverzeichnisse als Synchronisationsquelle."""
    if resolved_src in FORBIDDEN_EXACT_SOURCE_DIRS:
        return (
            f"Systemverzeichnis '{safe_str(resolved_src)}' darf nicht als Quellpfad "
            f"verwendet werden ({safe_str(raw_display)})"
        )
    for forbidden in FORBIDDEN_TREE_SOURCE_DIRS:
        if resolved_src == forbidden or forbidden in resolved_src.parents:
            return (
                f"System-/Kernel-Verzeichnis '{safe_str(resolved_src)}' darf nicht als Quellpfad "
                f"verwendet werden ({safe_str(raw_display)})"
            )
    return None


def parse_source_spec(raw: str, default_mode: str = "folder") -> Tuple[str, Path, str]:
    """
    Parst eine Quellpfad-Angabe:
    - Optionales führendes `-` entfernt den Pfad aus den Standardpfaden (`action="remove"`).
    - Optionales Präfix `folder:` (kompletter Ordner inkl. loser Dateien) oder
      `subfolders:` (nur Unterordner) bestimmt den Modus.
    - Der Pfad muss absolut sein oder mit `~` beginnen (Fail-Closed gegen Tippfehler).
    """
    if default_mode not in VALID_SOURCE_MODES:
        raise ValueError(f"Ungültiger Standardmodus: {safe_str(default_mode)}")

    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise ValueError(
            "Steuerzeichen oder Zeilenumbrüche im Quellpfad sind nicht erlaubt"
        )

    stripped = raw.strip()
    if not stripped:
        raise ValueError("Leerer Quellpfad ist nicht erlaubt")

    action = "add"
    body = stripped
    if stripped.startswith("-"):
        action = "remove"
        body = stripped[1:].strip()

    lower_body = body.lower()
    if lower_body.startswith("folder:"):
        mode = "folder"
        path_str = body[len("folder:") :].strip()
    elif lower_body.startswith("subfolders:"):
        mode = "subfolders"
        path_str = body[len("subfolders:") :].strip()
    else:
        mode = default_mode
        path_str = body

    if not path_str:
        raise ValueError(f"Quellpfad fehlt in Angabe: {safe_str(raw)}")

    if not (path_str.startswith("/") or path_str.startswith("~")):
        raise ValueError(
            f"Quellpfad muss absolut sein oder mit '~' beginnen: {safe_str(raw)}"
        )

    candidate = Path(path_str)
    if ".." in candidate.parts:
        raise ValueError(
            f"Pfad-Traversierung ('..') im Quellpfad ist nicht erlaubt: {safe_str(raw)}"
        )

    expanded_path = os.path.expanduser(path_str)
    abs_path = os.path.abspath(expanded_path)
    resolved_path = Path(expanded_path).resolve()
    if abs_path == "/" or str(resolved_path) == "/":
        raise ValueError(
            "Das Wurzelverzeichnis '/' darf nicht als Quellpfad verwendet werden"
        )
    forbidden_err = _validate_resolved_source_dir(resolved_path, raw)
    if forbidden_err:
        raise ValueError(forbidden_err)

    return action, candidate, mode


def _read_sources_file_strict(file_path: Path, required: bool) -> List[str]:
    """Liest eine Quellen-Datei nach dem Fail-Closed-Prinzip."""
    return _read_config_lines_strict(file_path, required=required, label="Quellen-Datei")


def load_sync_sources(
    *,
    dokumente_dir: Path = DEFAULT_DOKUMENTE,
    zotero_dir: Path = DEFAULT_ZOTERO,
    cli_add_sources: Optional[Sequence[str]] = None,
    cli_skip_sources: Optional[Sequence[str]] = None,
    sources_file: Optional[Path] = DEFAULT_SOURCES_FILE,
    require_sources_file: bool = False,
    extra_sources_files: Sequence[Path] = (),
) -> Tuple[List[SyncSource], List[Path]]:
    """
    Lädt die aktiven Synchronisationsquellen aus:
    1. Eingebauten Standardpfaden (`~/Dokumente` im Modus `subfolders`, `~/Zotero` im Modus `folder`)
    2. `extra_sources_files` (optional, z. B. `~/.config/proton-sync/sources.txt`, `sources.local.txt`)
    3. `sources_file` (standardmäßig `sources.txt` im Skript-Ordner; bei `--sources-file` Pflicht!)
    4. `cli_add_sources` (`--source` / `-s`) und `cli_skip_sources` (`--skip-source`)

    Gibt `(aktive_quellen, entfernte_standardpfade)` zurück.
    """
    builtin_defaults: List[SyncSource] = [
        SyncSource(path=dokumente_dir, mode="subfolders", origin="default"),
        SyncSource(path=zotero_dir, mode="folder", origin="default"),
    ]
    active: List[SyncSource] = list(builtin_defaults)
    removed_defaults: List[Path] = []

    def _apply_entry(raw_spec: str, origin: str, force_remove: bool = False) -> None:
        action, path, mode = parse_source_spec(raw_spec, default_mode="folder")
        if force_remove:
            action = "remove"

        if action == "add":
            removed_defaults[:] = [p for p in removed_defaults if not _sources_match(p, path)]
            for idx, existing in enumerate(active):
                if _sources_match(existing.path, path):
                    active[idx] = SyncSource(path=path, mode=mode, origin=origin)
                    return
            active.append(SyncSource(path=path, mode=mode, origin=origin))
            return

        # action == "remove"
        active[:] = [src for src in active if not _sources_match(src.path, path)]
        for builtin in builtin_defaults:
            if _sources_match(builtin.path, path) and not any(
                _sources_match(r, builtin.path) for r in removed_defaults
            ):
                removed_defaults.append(builtin.path)

    for extra_file in extra_sources_files:
        for line in _read_sources_file_strict(extra_file, required=False):
            _apply_entry(line, origin=f"file:{extra_file.name}")

    if sources_file is not None:
        for line in _read_sources_file_strict(sources_file, required=require_sources_file):
            _apply_entry(line, origin=f"file:{sources_file.name}")

    if cli_add_sources:
        for raw in cli_add_sources:
            _apply_entry(raw, origin="cli")

    if cli_skip_sources:
        for raw in cli_skip_sources:
            _apply_entry(raw, origin="cli", force_remove=True)

    return active, removed_defaults


def _format_source_entry(path_str: str, mode: str) -> str:
    return f"subfolders:{path_str}" if mode == "subfolders" else path_str


def _read_sources_raw_lines(file_path: Path) -> Tuple[List[str], bool]:
    """Liest vorhandene Rohzeilen (inkl. Kommentaren) einer Quellen-Datei (Fail-Closed)."""
    content = _open_and_read_config_text(
        file_path, required=False, label="Quellen-Datei"
    )
    if content is None:
        return [], False
    return content.splitlines(), True


def _write_sources_file_lines(file_path: Path, lines: Sequence[str]) -> None:
    """Schreibt die Quellen-Datei atomar mit Dateirechten 0600 und Symlink-/Ketten-Schutz."""
    expanded = file_path.expanduser()
    try:
        lst = os.lstat(expanded)
    except FileNotFoundError:
        lst = None

    if lst is not None:
        if stat.S_ISLNK(lst.st_mode):
            raise PermissionError(
                f"Quellen-Datei darf kein Symlink sein: {safe_str(expanded)}"
            )
        if not stat.S_ISREG(lst.st_mode):
            raise IsADirectoryError(
                f"Quellen-Datei ist keine reguläre Datei: {safe_str(expanded)}"
            )

    ancestor = expanded.parent
    while not os.path.lexists(ancestor) and ancestor != ancestor.parent:
        ancestor = ancestor.parent
    if os.path.lexists(ancestor):
        chain_err = _verify_secure_directory_chain(
            ancestor, reject_leaf_symlink=False
        )
        if chain_err:
            raise PermissionError(
                f"Unsicheres Zielverzeichnis für Quellen-Datei: {chain_err}"
            )

    expanded.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    chain_err = _verify_secure_directory_chain(
        expanded.parent, reject_leaf_symlink=False
    )
    if chain_err:
        raise PermissionError(
            f"Unsicheres Zielverzeichnis für Quellen-Datei: {chain_err}"
        )

    content = "\n".join(lines) + ("\n" if lines else "")
    fd, tmp_name = tempfile.mkstemp(prefix=".sources-tmp-", dir=str(expanded.parent))
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, expanded)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def add_default_source(
    file_path: Path,
    spec: str,
    default_mode: str = "folder",
    builtin_defaults: Sequence[SyncSource] = (),
) -> str:
    """Fügt einen Standardpfad dauerhaft zu `file_path` hinzu oder reaktiviert einen entfernten Standard."""
    action, path, mode = parse_source_spec(spec, default_mode=default_mode)
    if action != "add":
        raise ValueError(
            f"Zum Entfernen bitte '--remove-source' verwenden, nicht '{safe_str(spec)}'."
        )

    raw_lines, _ = _read_sources_raw_lines(file_path)
    formatted_entry = _format_source_entry(str(path), mode)
    matches_builtin_same_mode = any(
        _sources_match(b.path, path) and b.mode == mode for b in builtin_defaults
    )

    new_lines: List[str] = []
    replaced = False
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        try:
            line_action, line_path, _ = parse_source_spec(stripped, default_mode="folder")
        except ValueError:
            new_lines.append(line)
            continue
        if _sources_match(line_path, path):
            if line_action == "remove":
                continue
            if not matches_builtin_same_mode and not replaced:
                new_lines.append(formatted_entry)
                replaced = True
            continue
        new_lines.append(line)

    if not matches_builtin_same_mode and not replaced:
        new_lines.append(formatted_entry)

    _write_sources_file_lines(file_path, new_lines)
    return f"Standardpfad aktiviert: {safe_str(path)} (Modus: {mode})"


def remove_default_source(
    file_path: Path,
    spec: str,
    builtin_defaults: Sequence[SyncSource] = (),
) -> str:
    """Entfernt einen Standardpfad dauerhaft aus den aktiven Standardpfaden in `file_path`."""
    cleaned = spec.strip()
    if cleaned.startswith("-"):
        cleaned = cleaned[1:].strip()
    _, path, _ = parse_source_spec(cleaned, default_mode="folder")

    raw_lines, _ = _read_sources_raw_lines(file_path)
    is_builtin = any(_sources_match(b.path, path) for b in builtin_defaults)

    new_lines: List[str] = []
    has_remove_entry = False
    for line in raw_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        try:
            line_action, line_path, _ = parse_source_spec(stripped, default_mode="folder")
        except ValueError:
            new_lines.append(line)
            continue
        if _sources_match(line_path, path):
            if line_action == "add":
                continue
            if line_action == "remove":
                if not has_remove_entry and is_builtin:
                    new_lines.append(line)
                    has_remove_entry = True
                continue
        new_lines.append(line)

    if is_builtin and not has_remove_entry:
        new_lines.append(f"-{path}")

    _write_sources_file_lines(file_path, new_lines)
    return f"Standardpfad entfernt: {safe_str(path)}"


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
        seen_nfc: Dict[str, Path] = {}
        for child in children:
            result = classify_entry(child, policy, stats)
            if result is None:
                continue
            kind, st = result
            nfc_name = unicodedata.normalize("NFC", child.name)
            if nfc_name in seen_nfc:
                stats.errors.append(
                    f"Unicode-Namenskollision (NFC/NFD) in {safe_str(current)}: "
                    f"{safe_str(seen_nfc[nfc_name].name)} vs. {safe_str(child.name)}"
                )
                continue
            seen_nfc[nfc_name] = child
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
                env=_sanitized_cli_env(),
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
    dokumente_dir: Optional[Path] = None,
    zotero_dir: Optional[Path] = None,
    include_hidden: bool = False,
    stats: Optional[SyncStats] = None,
    exclude_patterns: Sequence[str] = (),
    allowed_devs: FrozenSet[int] = frozenset(),
    sources: Optional[Sequence[SyncSource]] = None,
) -> List[Tuple[Path, str, str]]:
    """
    Bestimmt alle zu synchronisierenden Top-Level-Ordner aus `sources` (oder
    rückwärtskompatibel aus `dokumente_dir` + `zotero_dir`) unter Berücksichtigung
    der Ausschlussliste `exclude_patterns` und erlaubter Dateisysteme (`allowed_devs`).
    Rückgabe: Liste von Tupeln (resolved_local_folder_path, remote_parent_path, folder_name)
    """
    if stats is None:
        stats = SyncStats()

    if sources is None:
        effective_sources: List[SyncSource] = []
        if dokumente_dir is not None:
            effective_sources.append(
                SyncSource(path=dokumente_dir, mode="subfolders", origin="default")
            )
        if zotero_dir is not None:
            effective_sources.append(
                SyncSource(path=zotero_dir, mode="folder", origin="default")
            )
    else:
        effective_sources = list(sources)

    targets: List[Tuple[Path, str, str]] = []
    seen_targets: Dict[str, Path] = {}
    base_dirs = [s.path.expanduser() for s in effective_sources]

    def _add_target(local_path: Path, remote_parent: str, folder_name: str) -> None:
        norm_key = normalize_for_match(folder_name)
        if norm_key in seen_targets:
            if seen_targets[norm_key] == local_path:
                return
            stats.errors.append(
                f"Namenskollision im Cloud-Ziel '{safe_str(remote_parent)}/{safe_str(folder_name)}': "
                f"{safe_str(seen_targets[norm_key])} vs. {safe_str(local_path)}"
            )
            return
        seen_targets[norm_key] = local_path
        targets.append((local_path, remote_parent, folder_name))

    for source in effective_sources:
        raw_src = source.path.expanduser()
        resolved_src = raw_src.resolve()

        if not (resolved_src.exists() and resolved_src.is_dir()):
            stats.errors.append(f"Quellordner nicht gefunden: {safe_str(source.path)}")
            continue

        forbidden_err = _validate_resolved_source_dir(resolved_src, source.path)
        if forbidden_err:
            stats.errors.append(forbidden_err)
            continue

        if source.mode == "subfolders":
            for entry in sorted(resolved_src.iterdir(), key=lambda p: p.name.lower()):
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
                    _add_target(entry, REMOTE_ROOT, entry.name)
                elif stat.S_ISREG(st.st_mode):
                    stats.ignored_loose_files.append(entry)
        else:
            # source.mode == "folder": ganzer Ordner inkl. Unterordnern und loser Dateien
            # (explizite Punkt-Ordner wie ~/.config werden auch ohne --include-hidden aufgenommen)
            logical_name = (
                raw_src.name
                if raw_src.name and raw_src.name not in (".", "..")
                else resolved_src.name
            )
            if logical_name.startswith(STAGING_PREFIX):
                stats.errors.append(
                    f"Ungültiger Zielordnername mit reserviertem Präfix '{safe_str(logical_name)}' "
                    f"(Pfad: {safe_str(source.path)})"
                )
                continue
            ok_name, reason = is_safe_node_name(logical_name)
            if not ok_name:
                stats.errors.append(
                    f"Ungültiger Zielordnername '{safe_str(logical_name)}' (Pfad: {safe_str(source.path)}): {reason}"
                )
                continue
            excluded, matched = is_excluded_path(raw_src, exclude_patterns, base_dirs)
            if excluded:
                stats.excluded_folders.append((resolved_src, matched or ""))
                continue
            _add_target(resolved_src, REMOTE_ROOT, logical_name)

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

            seen_nfc_dir: Dict[str, Path] = {}
            for child in children:
                result = classify_entry(child, policy, stats)
                if result is None:
                    continue
                kind, child_st = result
                nfc_name = unicodedata.normalize("NFC", child.name)
                if nfc_name in seen_nfc_dir:
                    stats.errors.append(
                        f"Unicode-Namenskollision (NFC/NFD) in {safe_str(l_dir)}: "
                        f"{safe_str(seen_nfc_dir[nfc_name].name)} vs. {safe_str(child.name)}"
                    )
                    continue
                seen_nfc_dir[nfc_name] = child
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


def _empty_dir_fd(dir_fd: int, errors: List[str]) -> None:
    """Leert ein Verzeichnis ausschließlich über `dir_fd` ohne Pfad-Traversierung."""
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    uid = os.geteuid()
    entries: List[Tuple[str, bool]] = []
    try:
        dup_fd = os.dup(dir_fd)
    except OSError as exc:
        errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
        return
    try:
        with os.scandir(dup_fd) as it:
            dup_fd = -1  # scandir schließt dup_fd beim Beenden
            for entry in it:
                entries.append((entry.name, entry.is_dir(follow_symlinks=False)))
    except OSError as exc:
        errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
        return
    finally:
        if dup_fd >= 0:
            try:
                os.close(dup_fd)
            except OSError:
                pass

    for name, is_dir in entries:
        if is_dir:
            child_fd = -1
            try:
                child_fd = os.open(name, dir_flags, dir_fd=dir_fd)
                child_st = os.fstat(child_fd)
                if not stat.S_ISDIR(child_st.st_mode) or child_st.st_uid != uid:
                    errors.append(
                        f"Staging-Aufräumen verweigert (unsicheres Unterverzeichnis): {safe_str(name)}"
                    )
                    continue
                _empty_dir_fd(child_fd, errors)
            except OSError as exc:
                errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
                continue
            finally:
                if child_fd >= 0:
                    try:
                        os.close(child_fd)
                    except OSError:
                        pass
            try:
                os.rmdir(name, dir_fd=dir_fd)
            except OSError as exc:
                errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
        else:
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError as exc:
                errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")


def _remove_staging_tree(path: Path) -> List[str]:
    """
    Entfernt einen privaten Staging-Bereich über Deskriptor-gebundene `dir_fd`-Aufrufe
    (`O_NOFOLLOW`), sodass Symlink-Tausch-Angriffe während des Aufräumens keine fremden
    Dateien oder Verzeichnisse außerhalb des Stagings löschen können.
    """
    errors: List[str] = []
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return errors
    except OSError as exc:
        return [f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}"]

    uid = os.geteuid()
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode) or lst.st_uid != uid:
        return [f"Staging-Aufräumen verweigert (unsicheres Ziel): {safe_str(path)}"]

    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    top_fd = -1
    try:
        top_fd = os.open(str(path), dir_flags)
        fst = os.fstat(top_fd)
        if (
            not stat.S_ISDIR(fst.st_mode)
            or fst.st_uid != uid
            or (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino)
        ):
            return [f"Staging-Aufräumen verweigert (Ziel verändert): {safe_str(path)}"]
        _empty_dir_fd(top_fd, errors)
    except OSError as exc:
        errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
    finally:
        if top_fd >= 0:
            try:
                os.close(top_fd)
            except OSError:
                pass

    if not errors:
        try:
            os.rmdir(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"Staging-Aufräumen fehlgeschlagen: {safe_str(exc)}")
    return errors


def _stage_verified_file(
    src: Path,
    dst: Path,
    dev: int,
    ino: int,
    allowed_roots: Sequence[Path] = (),
) -> None:
    """
    Stellt `dst` im privaten Staging-Bereich bereit:
    1. Bevorzugt Hardlink (`os.link(..., follow_symlinks=False)`) mit Vor- und Nachher-Inode-Prüfung.
    2. Fällt bei `EXDEV`, `EPERM` (`protected_hardlinks`), `EMLINK` o. ä. sicher auf eine
       FD-verifizierte Kopie (`O_RDONLY | O_NOFOLLOW | O_NONBLOCK` + `fstat`) zurück, statt
       jemals den ungeschützten Live-Quellpfad an `proton-drive` durchzureichen.
    """
    if allowed_roots:
        parent_err = _check_parents_not_symlinks(src, allowed_roots)
        if parent_err:
            raise ToctouError(parent_err)
    _verify_file_identity(src, dev, ino)

    try:
        os.link(src, dst, follow_symlinks=False)
    except OSError:
        # Sicherer FD-verifizierter Kopier-Fallback (kein Fallback auf Live-Quellpfade!)
        src_flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            src_fd = os.open(str(src), src_flags)
        except FileNotFoundError as exc:
            raise ToctouError(
                f"Lokale Datei vor Staging verschwunden {safe_str(src)}: {safe_str(exc)}"
            ) from exc
        except OSError as exc:
            if exc.errno == 40:  # ELOOP (Symlink)
                raise ToctouError(
                    f"TOCTOU-Schutz: {safe_str(src)} wurde durch einen Symlink ersetzt!"
                ) from exc
            raise

        dst_fd = -1
        dst_created = False
        try:
            src_st = os.fstat(src_fd)
            if not stat.S_ISREG(src_st.st_mode):
                raise ToctouError(
                    f"TOCTOU-Schutz: {safe_str(src)} ist keine reguläre Datei mehr!"
                )
            if ino and (src_st.st_dev, src_st.st_ino) != (dev, ino):
                raise ToctouError(
                    f"TOCTOU-Schutz: {safe_str(src)} wurde seit dem Scan durch eine andere Datei ersetzt!"
                )
            if allowed_roots:
                parent_err = _check_parents_not_symlinks(src, allowed_roots)
                if parent_err:
                    raise ToctouError(parent_err)

            dst_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
            )
            dst_fd = os.open(str(dst), dst_flags, 0o600)
            dst_created = True
            with os.fdopen(src_fd, "rb") as src_f, os.fdopen(dst_fd, "wb") as dst_f:
                src_fd = -1
                dst_fd = -1
                while chunk := src_f.read(1024 * 1024):
                    dst_f.write(chunk)
                dst_f.flush()
            try:
                os.utime(
                    dst,
                    ns=(src_st.st_atime_ns, src_st.st_mtime_ns),
                    follow_symlinks=False,
                )
            except (OSError, NotImplementedError):
                pass
            return
        except BaseException:
            if dst_created:
                try:
                    os.unlink(dst)
                except OSError:
                    pass
            raise
        finally:
            if src_fd >= 0:
                try:
                    os.close(src_fd)
                except OSError:
                    pass
            if dst_fd >= 0:
                try:
                    os.close(dst_fd)
                except OSError:
                    pass

    st = os.lstat(dst)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or (
        ino and (st.st_dev, st.st_ino) != (dev, ino)
    ):
        try:
            os.unlink(dst)
        except OSError:
            pass
        raise ToctouError(
            f"TOCTOU-Schutz: {safe_str(src)} wurde während des Stagings ausgetauscht!"
        )
    if allowed_roots:
        parent_err = _check_parents_not_symlinks(src, allowed_roots)
        if parent_err:
            try:
                os.unlink(dst)
            except OSError:
                pass
            raise ToctouError(parent_err)


def _link_verified(
    src: Path,
    dst: Path,
    dev: int,
    ino: int,
    allowed_roots: Sequence[Path] = (),
) -> None:
    """Rückwärtskompatibler Alias für `_stage_verified_file`."""
    _stage_verified_file(src, dst, dev, ino, allowed_roots=allowed_roots)


def _private_cache_dir() -> Optional[Path]:
    candidates: List[Path] = []
    xdg_cache = os.environ.get("XDG_CACHE_HOME", "").strip()
    if xdg_cache and os.path.isabs(xdg_cache):
        candidates.append(Path(xdg_cache) / "proton-sync")
    candidates.append(Path.home() / ".cache" / "proton-sync")

    uid = os.geteuid()
    for cache_dir in candidates:
        try:
            ancestor = cache_dir
            while not os.path.lexists(ancestor) and ancestor != ancestor.parent:
                ancestor = ancestor.parent
            if os.path.lexists(ancestor):
                if (
                    _verify_secure_directory_chain(
                        ancestor, reject_leaf_symlink=False
                    )
                    is not None
                ):
                    continue
            cache_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            st = os.lstat(cache_dir)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
                continue
            if st.st_mode & 0o077:
                os.chmod(cache_dir, 0o700)
            if (
                _verify_secure_directory_chain(
                    cache_dir, reject_leaf_symlink=True
                )
                is not None
            ):
                continue
            return cache_dir
        except OSError:
            continue
    return None


class StagingArea:
    """
    Privater Staging-Bereich (`0700`, zufälliger Name) ausschließlich unter einem
    vertrauenswürdigen privaten Verzeichnis (`~/.cache/proton-sync` bzw. Lock-Verzeichnis)
    – niemals innerhalb der synchronisierten Quellordner.
    `proton-drive` erhält nur Pfade in diesem Bereich, sodass nachträglich in die
    echten Ordner gelegte Dateien/Symlinks niemals mit hochgeladen werden.
    """

    def __init__(self, roots: Sequence[Path], enabled: bool = True) -> None:
        self.roots = [Path(r) for r in roots]
        self.enabled = enabled
        self._base_dir: Optional[Path] = None
        self._failed = False
        self._counter = 0

    def _get_base_dir(self) -> Optional[Path]:
        if not self.enabled or self._failed:
            return None
        if self._base_dir is not None:
            return self._base_dir

        candidates: List[Path] = []
        cache_dir = _private_cache_dir()
        if cache_dir is not None:
            candidates.append(cache_dir)
        try:
            lock_dir = SingleInstanceLock._select_lock_dir()
            if lock_dir not in candidates:
                candidates.append(lock_dir)
        except (OSError, PermissionError):
            pass

        uid = os.geteuid()
        for priv_dir in candidates:
            if (
                _verify_secure_directory_chain(priv_dir, reject_leaf_symlink=True)
                is not None
            ):
                continue
            try:
                base = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=str(priv_dir)))
            except OSError:
                continue
            try:
                os.chmod(base, 0o700)
                st = os.lstat(base)
                if (
                    not stat.S_ISDIR(st.st_mode)
                    or st.st_uid != uid
                    or (st.st_mode & 0o077) != 0
                ):
                    _remove_staging_tree(base)
                    continue
            except OSError:
                _remove_staging_tree(base)
                continue
            self._base_dir = base
            return base

        self._failed = True
        return None

    def new_slot(self, dev: int = 0) -> Optional[Path]:
        _ = dev  # Signatur-Kompatibilität; Staging nutzt immer privaten Bereich + FD-Fallback
        base = self._get_base_dir()
        if base is None:
            return None
        self._counter += 1
        slot = base / f"{self._counter:06d}"
        try:
            slot.mkdir(mode=0o700)
            st = os.lstat(slot)
            if (
                not stat.S_ISDIR(st.st_mode)
                or st.st_uid != os.geteuid()
                or (st.st_mode & 0o077) != 0
            ):
                _remove_staging_tree(slot)
                return None
        except OSError:
            return None
        return slot

    def discard(self, slot: Optional[Path]) -> List[str]:
        if slot is None:
            return []
        return _remove_staging_tree(slot)

    def cleanup(self) -> List[str]:
        if self._base_dir is None:
            return []
        errs = _remove_staging_tree(self._base_dir)
        self._base_dir = None
        return errs

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
        env=_sanitized_cli_env(),
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
            if len(buf) > MAX_STREAM_LINE_BYTES:
                _emit(buf[:MAX_STREAM_LINE_BYTES])
                buf = buf[MAX_STREAM_LINE_BYTES:]
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

    # 1. Bevorzugt: kompletter Upload aus dem privaten Staging (ein CLI-Aufruf; kein ungeschützter Fallback)
    if staging is not None:
        slot = staging.new_slot(action.dev)
        if slot is None:
            return [
                f"Staging-Bereich konnte nicht sicher angelegt werden – Upload von "
                f"{safe_str(action.local_path)} abgebrochen."
            ]
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
                _stage_verified_file(
                    action.local_path / member.rel,
                    dst,
                    member.dev,
                    member.ino,
                    allowed_roots=allowed_roots,
                )
        except (ToctouError, OSError) as exc:
            staged_errors.append(str(exc))
            staged_errors.extend(staging.discard(slot))
            return staged_errors

        upload_err = _cli_upload(
            proton_bin, conflict_strategy, [str(tree_root)], action.remote_parent, timeout_sec
        )
        staged_errors.extend(staging.discard(slot))
        if upload_err:
            staged_errors.append(upload_err)
        return staged_errors

    # 2. Expliziter Modus ohne Staging (--no-staging): Ordner einzeln anlegen, Dateien verifiziert hochladen
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
    slot: Optional[Path] = None

    if staging is not None:
        slot = staging.new_slot(batch[0].dev if batch else 0)
        if slot is None:
            return [
                f"Staging-Bereich konnte nicht sicher angelegt werden – Datei-Batch für "
                f"{safe_str(remote_parent)} abgebrochen."
            ]

    for idx, action in enumerate(batch):
        ok, err = verify_action_before_execution(action, allowed_roots)
        if not ok:
            errors.append(err)
            continue

        if staging is not None:
            assert slot is not None
            sub = slot / f"{idx:04d}"
            try:
                sub.mkdir(mode=0o700)
                dst = sub / action.target_name
                _stage_verified_file(
                    action.local_path,
                    dst,
                    action.dev,
                    action.ino,
                    allowed_roots=allowed_roots,
                )
            except (ToctouError, OSError) as exc:
                errors.append(str(exc))
                continue
            upload_paths.append(str(dst))
        else:
            upload_paths.append(str(action.local_path))

    try:
        if upload_paths:
            upload_err = _cli_upload(
                proton_bin, conflict_strategy, upload_paths, remote_parent, timeout_sec
            )
            if upload_err:
                errors.append(upload_err)
    finally:
        if slot is not None and staging is not None:
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
        prog="sync_proton_drive.py",
        description=(
            "Synchronisiert konfigurierbare Standardordner (standardmäßig Unterordner von ~/Dokumente "
            "sowie ~/Zotero) mit Proton Drive (/my-files)."
        ),
    )
    parser.add_argument(
        "--dokumente",
        type=Path,
        default=DEFAULT_DOKUMENTE,
        help="Pfad zum Dokumente-Ordner (Standard: ~/Dokumente bzw. ~/Documents).",
    )
    parser.add_argument(
        "--zotero",
        type=Path,
        default=DEFAULT_ZOTERO,
        help="Pfad zum Zotero-Ordner (Standard: ~/Zotero).",
    )
    parser.add_argument(
        "--source",
        "-s",
        action="append",
        default=[],
        metavar="PFAD",
        help=(
            "Zusätzlicher Quellordner nur für diesen Lauf "
            "(z. B. `~/.config`, `folder:/pfad` oder `subfolders:/pfad`)."
        ),
    )
    parser.add_argument(
        "--skip-source",
        action="append",
        default=[],
        metavar="PFAD",
        help="Überspringt einen konfigurierten Standardpfad nur für diesen Lauf (z. B. `~/Zotero`).",
    )
    parser.add_argument(
        "--sources-file",
        type=Path,
        default=None,
        help=(
            "Explizite Datei mit Standardpfaden (Fail-Closed bei Nichtvorhandensein; "
            "Standard ohne Flag: <Skript-Ordner>/sources.txt falls vorhanden)."
        ),
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="Zeigt alle aktiven Standardpfade (und deaktivierte Standardpfade) an und beendet das Skript.",
    )
    parser.add_argument(
        "--add-source",
        action="append",
        default=[],
        metavar="PFAD",
        help=(
            "Fügt einen Standardpfad dauerhaft zu sources.txt (bzw. --sources-file) hinzu "
            "und beendet das Skript."
        ),
    )
    parser.add_argument(
        "--remove-source",
        action="append",
        default=[],
        metavar="PFAD",
        help=(
            "Entfernt einen Standardpfad dauerhaft aus den aktiven Standardpfaden in sources.txt "
            "(bzw. --sources-file) und beendet das Skript."
        ),
    )
    parser.add_argument(
        "--source-mode",
        choices=list(VALID_SOURCE_MODES),
        default="folder",
        help=(
            "Modus für `--add-source`: 'folder' (Standard, kompletter Ordner inkl. loser Dateien) "
            "oder 'subfolders' (nur Unterordner)."
        ),
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
            "Explizite Datei mit Ausschlussmustern (Fail-Closed bei Nichtvorhandensein; "
            "Standard ohne Flag: <Skript-Ordner>/exclude.txt falls vorhanden)."
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
        "--allow-sensitive",
        action="store_true",
        help=(
            "Deaktiviert die eingebauten Sicherheits-Ausschlüsse für Schlüssel, Tresore, "
            "Browser-Profile und Proton-/CLI-Tokens (`SENSITIVE_DEFAULT_EXCLUDES`)."
        ),
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
        help="Pfad zur proton-drive ausführbaren Datei (Standard: /usr/bin/proton-drive bzw. /usr/local/bin/proton-drive).",
    )
    return parser.parse_args(argv)


def _print_sources_summary(
    active_sources: Sequence[SyncSource],
    removed_defaults: Sequence[Path],
    sources_file: Path,
) -> None:
    print(f"Konfigurierte Standardpfade (Datei: {safe_str(sources_file)}):")
    if not active_sources:
        print("  (keine aktiven Standardpfade)")
    for src in active_sources:
        raw_src = src.path.expanduser()
        logical_name = (
            raw_src.name
            if raw_src.name and raw_src.name not in (".", "..")
            else raw_src.resolve().name
        )
        remote_target = (
            f"{REMOTE_ROOT}/<Unterordner>"
            if src.mode == "subfolders"
            else f"{REMOTE_ROOT}/{logical_name}"
        )
        print(
            f"  [+] {safe_str(src.path)}  [Modus: {src.mode}, Ziel: {safe_str(remote_target)}, Quelle: {safe_str(src.origin)}]"
        )
    if removed_defaults:
        print("Deaktivierte eingebaute Standardpfade:")
        for rem in removed_defaults:
            print(f"  [-] {safe_str(rem)}")


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    explicit_sources_file = args.sources_file is not None
    effective_sources_file = (
        args.sources_file if explicit_sources_file else DEFAULT_SOURCES_FILE
    )
    extra_sources_files = tuple(
        f
        for f in (DEFAULT_USER_SOURCES_FILE, DEFAULT_LOCAL_SOURCES_FILE)
        if not _sources_match(f, effective_sources_file)
    )

    if args.add_source or args.remove_source or args.list_sources:
        try:
            inherited_sources, _ = load_sync_sources(
                dokumente_dir=args.dokumente,
                zotero_dir=args.zotero,
                sources_file=None,
                extra_sources_files=extra_sources_files,
            )
            for spec in args.remove_source:
                print(
                    remove_default_source(
                        effective_sources_file,
                        spec,
                        builtin_defaults=inherited_sources,
                    )
                )
            for spec in args.add_source:
                print(
                    add_default_source(
                        effective_sources_file,
                        spec,
                        default_mode=args.source_mode,
                        builtin_defaults=inherited_sources,
                    )
                )
            active_sources, removed_defaults = load_sync_sources(
                dokumente_dir=args.dokumente,
                zotero_dir=args.zotero,
                cli_add_sources=args.source,
                cli_skip_sources=args.skip_source,
                sources_file=effective_sources_file,
                require_sources_file=explicit_sources_file
                and not (args.add_source or args.remove_source),
                extra_sources_files=extra_sources_files,
            )
        except (OSError, PermissionError, UnicodeDecodeError, ValueError) as exc:
            print(
                f"FEHLER bei der Verwaltung der Standardpfade: {safe_str(exc)}",
                file=sys.stderr,
            )
            return 2
        _print_sources_summary(active_sources, removed_defaults, effective_sources_file)
        return 0

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

    try:
        active_sources, _ = load_sync_sources(
            dokumente_dir=args.dokumente,
            zotero_dir=args.zotero,
            cli_add_sources=args.source,
            cli_skip_sources=args.skip_source,
            sources_file=effective_sources_file,
            require_sources_file=explicit_sources_file,
            extra_sources_files=extra_sources_files,
        )
    except (OSError, PermissionError, UnicodeDecodeError, ValueError) as exc:
        print(
            f"FEHLER beim Laden der Standardpfade (Fail-Closed-Abbruch): {safe_str(exc)}",
            file=sys.stderr,
        )
        return 2

    if not active_sources:
        print(
            "FEHLER: Keine aktiven Standardpfade zum Synchronisieren konfiguriert "
            "(prüfe sources.txt bzw. --add-source / --source).",
            file=sys.stderr,
        )
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
            include_sensitive_defaults=not args.allow_sensitive,
        )
    except (OSError, PermissionError, UnicodeDecodeError, ValueError) as exc:
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
                active_sources=active_sources,
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
    active_sources: Sequence[SyncSource],
) -> int:
    stats = SyncStats()
    base_dirs: List[Path] = []
    allowed_roots: List[Path] = []
    for src in active_sources:
        expanded = src.path.expanduser()
        resolved = expanded.resolve()
        if _validate_resolved_source_dir(resolved, src.path) is not None:
            continue
        base_dirs.append(expanded)
        allowed_roots.append(resolved)

    allowed_devs: Set[int] = set()
    if not args.cross_filesystems:
        for root in allowed_roots:
            try:
                allowed_devs.add(os.stat(root).st_dev)
            except OSError:
                pass

    cache_dir = _private_cache_dir()
    if cache_dir is not None:
        for stale in find_stale_staging_dirs([cache_dir]):
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

    for stale in find_stale_staging_dirs(allowed_roots):
        stats.warnings.append(
            f"Unerwarteter Staging-Eintrag im Quellordner gefunden (wird nicht automatisch gelöscht): {safe_str(stale)}"
        )

    targets = collect_sync_targets(
        include_hidden=args.include_hidden,
        stats=stats,
        exclude_patterns=exclude_patterns,
        allowed_devs=frozenset(allowed_devs),
        sources=active_sources,
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
    if not args.allow_live_zotero:
        checked_zotero_dirs: Set[Path] = set()
        for target_dir, _, _ in targets:
            if target_dir in checked_zotero_dirs:
                continue
            checked_zotero_dirs.add(target_dir)
            zotero_reason = zotero_db_state(target_dir)
            if zotero_reason:
                for side_name in ZOTERO_SQLITE_SIDE_FILES:
                    candidate = target_dir / side_name
                    if os.path.lexists(candidate):
                        locked_skip_files.add(candidate.resolve())
                stats.warnings.append(
                    f"zotero.sqlite* in {safe_str(target_dir)} übersprungen ({zotero_reason}), um korrupte Backups zu "
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
    for src in active_sources:
        resolved_src = src.path.expanduser().resolve()
        mode_desc = (
            "nur Unterordner, keine losen Dateien"
            if src.mode == "subfolders"
            else "kompletter Ordner inkl. loser Dateien"
        )
        print(f"Quelle ({src.mode:<10}): {safe_str(resolved_src)} ({mode_desc})")
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
            f"Ignorierte lose Dateien in 'subfolders'-Quellen "
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
    print(f"Ignorierte lose Dateien (subfolders)  : {len(stats.ignored_loose_files)}")
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
