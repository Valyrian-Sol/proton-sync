#!/usr/bin/env python3
"""
Proton Drive Sync-Script (Einweg-Synchronisation PC -> Proton Drive)

Synchronisiert:
1. Alle Unterordner in ~/Dokumente -> /my-files/<Unterordner>
   (lose Dateien direkt in ~/Dokumente werden ignoriert!)
2. Den Ordner ~/Zotero -> /my-files/Zotero

Regeln:
- Bestimmte Ordner können über `DEFAULT_EXCLUDED_FOLDERS`, `exclude.txt` oder
  `--exclude` / `-x` von der Synchronisation ausgeschlossen werden.
- Neue Dateien und Ordner werden hochgeladen.
- Dateien, die in der Cloud älter sind als auf dem PC, werden durch die
  PC-Version ersetzt (als neue Revision über `-f create-new-revision -d merge`).
- Dateien, die in der Cloud neuer oder gleich alt (bzw. inhaltsgleich per SHA-1)
  sind, werden nicht überschrieben.
- Es werden NIEMALS Dateien oder Ordner gelöscht, ohne dass sie durch eine
  neuere Version ersetzt werden (keine Löschbefehle, Ordner-Strategie `merge`).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


def _default_documents_dir() -> Path:
    dok = Path.home() / "Dokumente"
    docs = Path.home() / "Documents"
    if not dok.exists() and docs.exists():
        return docs
    return dok


PROTON_DRIVE_BIN = shutil.which("proton-drive") or "/usr/bin/proton-drive"
REMOTE_ROOT = "/my-files"
DEFAULT_DOKUMENTE = _default_documents_dir()
DEFAULT_ZOTERO = Path.home() / "Zotero"
DEFAULT_EXCLUDE_FILE = Path(__file__).resolve().parent / "exclude.txt"

# Feste Ausschlussliste im Skript (Ordnernamen, relative Pfade wie "Projekte/Archiv",
# Glob-Muster wie "node_modules" oder absolute Pfade wie "~/Dokumente/Videos"):
DEFAULT_EXCLUDED_FOLDERS: List[str] = [
    # Beispiele:
    # "Videos",
    # "node_modules",
    # "__pycache__",
]


@dataclass
class RemoteNode:
    name: str
    node_type: str  # "file" | "folder"
    modification_time: Optional[datetime.datetime] = None
    claimed_mtime: Optional[datetime.datetime] = None
    claimed_size: Optional[int] = None
    claimed_sha1: Optional[str] = None

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
    return name.replace("/", r"\/")


def join_remote_path(parent: str, name: str) -> str:
    parent_clean = parent.rstrip("/")
    return f"{parent_clean}/{escape_remote_segment(name)}"


def compute_sha1(file_path: Path) -> str:
    h = hashlib.sha1()
    with file_path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().lower()


def get_local_mtime_utc(file_path: Path) -> datetime.datetime:
    st = file_path.stat()
    return datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)


def load_exclude_patterns(
    cli_excludes: Optional[Sequence[str]] = None,
    exclude_file: Optional[Path] = DEFAULT_EXCLUDE_FILE,
    default_excludes: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Lädt und kombiniert alle Ordner-Ausschlussmuster aus:
    1. `default_excludes` (bzw. `DEFAULT_EXCLUDED_FOLDERS`)
    2. `exclude_file` (standardmäßig `exclude.txt` im Skript-Ordner, falls vorhanden)
    3. `cli_excludes` (`--exclude` / `-x` Parameter, auch kommagetrennt)
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

    if exclude_file is not None and exclude_file.exists() and exclude_file.is_file():
        for raw_line in exclude_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line not in patterns:
                patterns.append(line)

    if cli_excludes:
        for raw in cli_excludes:
            for part in raw.split(","):
                cleaned = part.strip()
                if cleaned and cleaned not in patterns:
                    patterns.append(cleaned)

    return patterns


def is_excluded_folder(
    folder_path: Path,
    exclude_patterns: Sequence[str],
    base_dirs: Sequence[Path] = (),
) -> Tuple[bool, Optional[str]]:
    """
    Prüft, ob `folder_path` durch eines der Muster in `exclude_patterns`
    ausgeschlossen ist.

    Unterstützte Musterformate:
    - Einfacher Ordnername oder Glob-Muster (ohne '/'), z. B.:
      `"Videos"`, `"node_modules"`, `"*backup*"`
    - Relativer Pfad ab `~/Dokumente` oder `~/Zotero` (bzw. `base_dirs`), z. B.:
      `"Projekte/Archiv"`, `"Zotero/storage"`
    - Absoluter Pfad oder `~`-Pfad, z. B.:
      `"~/Dokumente/Videos"`, `"/home/<user>/Dokumente/Videos"`

    Gibt `(True, passendes_muster)` oder `(False, None)` zurück.
    """
    if not exclude_patterns:
        return False, None

    resolved_folder = folder_path.expanduser().resolve()
    folder_name = folder_path.name

    # Relative Pfade zu den Basisordnern vorbereiten (z. B. "Projekte/Archiv" oder "Zotero/storage")
    rel_candidates: List[str] = []
    for base in base_dirs:
        resolved_base = base.expanduser().resolve()
        try:
            rel = resolved_folder.relative_to(resolved_base).as_posix()
            if rel != ".":
                rel_candidates.append(rel)
                rel_candidates.append(f"{resolved_base.name}/{rel}")
            else:
                rel_candidates.append(resolved_base.name)
        except ValueError:
            continue

    for raw_pattern in exclude_patterns:
        pattern = raw_pattern.strip().rstrip("/")
        if not pattern:
            continue

        # 1. Absoluter Pfad oder ~/... Pfad
        if pattern.startswith("/") or pattern.startswith("~"):
            expanded_pat = Path(pattern).expanduser().resolve().as_posix()
            folder_posix = resolved_folder.as_posix()
            if (
                folder_posix == expanded_pat
                or folder_posix.startswith(expanded_pat + "/")
                or fnmatch.fnmatchcase(folder_posix, expanded_pat)
            ):
                return True, raw_pattern
            continue

        # 2. Muster ohne '/' -> prüft den Ordnernamen direkt (auf jeder Ebene)
        if "/" not in pattern:
            if fnmatch.fnmatchcase(folder_name, pattern):
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


def has_excluded_descendant(
    folder_path: Path,
    exclude_patterns: Sequence[str],
    include_hidden: bool,
    base_dirs: Sequence[Path] = (),
) -> bool:
    """
    Prüft rekursiv, ob sich innerhalb eines neuen lokalen Ordners mindestens ein
    ausgeschlossener Unterordner befindet (damit der Elternordner nicht blind
    als Komplett-Paket inklusive des ausgeschlossenen Unterordners hochgeladen wird).
    """
    if not exclude_patterns:
        return False

    stack: List[Path] = [folder_path]
    while stack:
        current = stack.pop()
        try:
            for child in current.iterdir():
                if child.is_symlink() or not child.is_dir():
                    continue
                if child.name.startswith(".") and not include_hidden:
                    continue
                excluded, _ = is_excluded_folder(child, exclude_patterns, base_dirs)
                if excluded:
                    return True
                stack.append(child)
        except OSError:
            continue
    return False


def plan_new_folder_with_exclusions(
    local_dir: Path,
    remote_parent: str,
    include_hidden: bool,
    exclude_patterns: Sequence[str],
    base_dirs: Sequence[Path],
    stats: SyncStats,
) -> List[SyncAction]:
    """
    Plant den Upload eines in der Cloud noch nicht existierenden Ordners `local_dir`.
    - Falls KEIN Unterordner darin ausgeschlossen ist: 1 kompletter Ordner-Upload (`new_folder`).
    - Falls mindestens ein Unterordner darin ausgeschlossen ist:
      Legt den Elternordner in der Cloud an (`create_remote_folder`) und plant nur
      die erlaubten Dateien und Unterordner ein.
    """
    if not has_excluded_descendant(local_dir, exclude_patterns, include_hidden, base_dirs):
        stats.new_folders += 1
        return [
            SyncAction(
                local_path=local_dir,
                remote_parent=remote_parent,
                reason="new_folder",
                details="Neuer Ordner (inkl. Inhalt)",
            )
        ]

    actions: List[SyncAction] = [
        SyncAction(
            local_path=local_dir,
            remote_parent=remote_parent,
            reason="create_remote_folder",
            details="Ordner in Cloud anlegen (enthält ausgeschlossene Unterordner)",
        )
    ]
    stats.new_folders += 1
    remote_this = join_remote_path(remote_parent, local_dir.name)

    try:
        children = sorted(local_dir.iterdir(), key=lambda p: p.name.lower())
    except OSError as exc:
        stats.errors.append(f"Konnte lokalen Ordner nicht lesen {local_dir}: {exc}")
        return actions

    for child in children:
        if child.name.startswith(".") and not include_hidden:
            continue
        if child.is_symlink():
            continue

        if child.is_dir():
            excluded, matched = is_excluded_folder(child, exclude_patterns, base_dirs)
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
                )
            )
        elif child.is_file():
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
    remote_path: str, proton_bin: str = PROTON_DRIVE_BIN, retries: int = 3
) -> Optional[Dict[str, RemoteNode]]:
    """
    Liest den Inhalt eines Remote-Ordners via `proton-drive filesystem list -j <remote_path>`.
    Gibt ein Dictionary {dateiname: RemoteNode} zurück oder None bei einem Fehler.
    Beinhaltet automatische Wiederholungsversuche (Retries) bei temporären CLI-/API-Sperren.
    """
    cmd = [proton_bin, "filesystem", "list", "-j", remote_path]
    raw_items = None

    for attempt in range(retries):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            stdout = proc.stdout.strip()
            if not stdout:
                return {}
            try:
                raw_items = json.loads(stdout)
                break
            except json.JSONDecodeError:
                pass
        if attempt < retries - 1:
            time.sleep(0.8 * (attempt + 1))

    if raw_items is None:
        return None

    entries: Dict[str, RemoteNode] = {}
    for item in raw_items:
        name_obj = item.get("name") or {}
        if isinstance(name_obj, dict):
            name = name_obj.get("value")
        else:
            name = str(name_obj)
        if not name:
            continue

        node_type = item.get("type", "file")
        mod_time = parse_iso_timestamp(item.get("modificationTime"))

        claimed_mtime = None
        claimed_size = None
        claimed_sha1 = None
        active_rev = item.get("activeRevision")
        if isinstance(active_rev, dict):
            claimed_mtime = parse_iso_timestamp(active_rev.get("claimedModificationTime"))
            if isinstance(active_rev.get("claimedSize"), int):
                claimed_size = active_rev["claimedSize"]
            digests = active_rev.get("claimedDigests")
            if isinstance(digests, dict) and isinstance(digests.get("sha1"), str):
                claimed_sha1 = digests["sha1"].lower()

        entries[name] = RemoteNode(
            name=name,
            node_type=node_type,
            modification_time=mod_time,
            claimed_mtime=claimed_mtime,
            claimed_size=claimed_size,
            claimed_sha1=claimed_sha1,
        )
    return entries


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
    Rückgabe: Liste von Tupeln (local_folder_path, remote_parent_path, folder_name)
    """
    targets: List[Tuple[Path, str, str]] = []
    base_dirs = [dokumente_dir, zotero_dir]

    if dokumente_dir.exists() and dokumente_dir.is_dir():
        for entry in sorted(dokumente_dir.iterdir(), key=lambda p: p.name.lower()):
            if entry.name.startswith(".") and not include_hidden:
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir():
                excluded, matched = is_excluded_folder(entry, exclude_patterns, base_dirs)
                if excluded:
                    stats.excluded_folders.append((entry, matched or ""))
                    continue
                targets.append((entry, REMOTE_ROOT, entry.name))
            elif entry.is_file():
                stats.ignored_loose_files.append(entry)
    else:
        stats.errors.append(f"Dokumente-Ordner nicht gefunden: {dokumente_dir}")

    if zotero_dir.exists() and zotero_dir.is_dir():
        excluded, matched = is_excluded_folder(zotero_dir, exclude_patterns, base_dirs)
        if excluded:
            stats.excluded_folders.append((zotero_dir, matched or ""))
        else:
            targets.append((zotero_dir, REMOTE_ROOT, zotero_dir.name))
    else:
        stats.errors.append(f"Zotero-Ordner nicht gefunden: {zotero_dir}")

    return targets


def should_upload_existing_file(
    local_file: Path,
    remote_node: RemoteNode,
    mtime_tolerance_sec: float = 1.0,
) -> Tuple[bool, str, str]:
    """
    Prüft für eine lokal und in der Cloud existierende Datei, ob sie hochgeladen
    werden soll.
    Gibt (should_upload, category, details) zurück.
    Kategorien:
      - "identical": gleicher Inhalt (Größe + SHA-1 identisch)
      - "updated_file": PC-Version ist neuer als Cloud-Version und Inhalt unterscheidet sich
      - "remote_newer_or_equal": Cloud-Version ist neuer oder gleich alt
    """
    st = local_file.stat()
    local_size = st.st_size
    local_mtime = datetime.datetime.fromtimestamp(st.st_mtime, tz=datetime.timezone.utc)
    remote_mtime = remote_node.effective_mtime

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
    #    Prüfen, ob der Inhalt trotz neuerem Zeitstempel bereits identisch ist (SHA-1 + Größe)
    if (
        remote_node.claimed_size is not None
        and remote_node.claimed_size == local_size
        and remote_node.claimed_sha1
    ):
        local_sha1 = compute_sha1(local_file)
        if local_sha1 == remote_node.claimed_sha1:
            return (
                False,
                "identical",
                f"SHA-1 identisch ({local_sha1[:10]}...)",
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
) -> List[SyncAction]:
    """
    Durchläuft `local_dir` ebenenweise (BFS) und nutzt parallele `filesystem list -j`
    Abfragen für bereits in der Cloud vorhandene Unterordner.
    Ausgeschlossene Ordner (`exclude_patterns`) werden komplett übersprungen.
    """
    actions: List[SyncAction] = []

    # Queue von Tupeln: (lokaler_ordner, remote_ordner_pfad)
    current_level: List[Tuple[Path, str]] = [(local_dir, remote_dir_path)]

    while current_level:
        # Alle Remote-Ordner der aktuellen Ebene parallel abfragen
        future_to_pair = {
            executor.submit(list_remote_directory, r_path, proton_bin): (l_dir, r_path)
            for l_dir, r_path in current_level
        }

        next_level: List[Tuple[Path, str]] = []

        for future in concurrent.futures.as_completed(future_to_pair):
            l_dir, r_path = future_to_pair[future]
            stats.folders_checked += 1
            remote_entries = future.result()

            if remote_entries is None:
                stats.errors.append(
                    f"Konnte Remote-Ordner nicht auflisten: {r_path} (lokal: {l_dir})"
                )
                continue

            try:
                children = sorted(l_dir.iterdir(), key=lambda p: p.name.lower())
            except OSError as exc:
                stats.errors.append(f"Konnte lokalen Ordner nicht lesen {l_dir}: {exc}")
                continue

            for child in children:
                if child.name.startswith(".") and not include_hidden:
                    continue
                if child.is_symlink():
                    continue

                remote_node = remote_entries.get(child.name)

                if child.is_dir():
                    excluded, matched = is_excluded_folder(
                        child, exclude_patterns, base_dirs
                    )
                    if excluded:
                        stats.excluded_folders.append((child, matched or ""))
                        continue

                    if remote_node is None or remote_node.node_type != "folder":
                        # Ordner existiert noch nicht in der Cloud
                        actions.extend(
                            plan_new_folder_with_exclusions(
                                local_dir=child,
                                remote_parent=r_path,
                                include_hidden=include_hidden,
                                exclude_patterns=exclude_patterns,
                                base_dirs=base_dirs,
                                stats=stats,
                            )
                        )
                    else:
                        # Ordner existiert bereits -> in nächster BFS-Ebene prüfen
                        child_remote_path = join_remote_path(r_path, child.name)
                        next_level.append((child, child_remote_path))

                elif child.is_file():
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
                                child, remote_node, mtime_tolerance_sec=mtime_tolerance_sec
                            )
                        except OSError as exc:
                            stats.errors.append(f"Fehler beim Lesen von {child}: {exc}")
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


def execute_upload_batches(
    actions: List[SyncAction],
    proton_bin: str,
    conflict_strategy: str = "create-new-revision",
    batch_size: int = 50,
    dry_run: bool = False,
    verbose: bool = False,
) -> List[str]:
    """
    Führt zuerst ggf. notwendige Remote-Ordner-Erstellungen (`create_remote_folder`)
    aus und gruppiert anschließend alle Datei-/Ordner-Uploads nach ihrem Zielordner
    (`remote_parent`) via:
    `proton-drive filesystem upload -f <conflict_strategy> -d merge <pfade...> <remote_parent>`
    """
    errors: List[str] = []
    if not actions:
        return errors

    mkdir_actions = [a for a in actions if a.reason == "create_remote_folder"]
    upload_actions = [a for a in actions if a.reason != "create_remote_folder"]

    for a in mkdir_actions:
        if dry_run or verbose:
            print(
                f"  [ORDNER ANLEGEN] {a.local_path} -> {join_remote_path(a.remote_parent, a.local_path.name)} ({a.details})"
            )
        if dry_run:
            continue
        cmd = [
            proton_bin,
            "filesystem",
            "create-folder",
            a.remote_parent,
            a.local_path.name,
        ]
        proc = subprocess.run(cmd, text=True)
        if proc.returncode != 0:
            errors.append(
                f"Ordner-Erstellung fehlgeschlagen (Exit-Code {proc.returncode}) für {a.local_path.name} in {a.remote_parent}"
            )

    # Gruppieren nach remote_parent unter Beibehaltung der Reihenfolge
    grouped: Dict[str, List[SyncAction]] = {}
    for act in upload_actions:
        grouped.setdefault(act.remote_parent, []).append(act)

    for remote_parent, group in grouped.items():
        for i in range(0, len(group), batch_size):
            batch = group[i : i + batch_size]
            local_paths = [str(a.local_path) for a in batch]
            cmd = [
                proton_bin,
                "filesystem",
                "upload",
                "-f",
                conflict_strategy,
                "-d",
                "merge",
                *local_paths,
                remote_parent,
            ]

            if dry_run or verbose:
                for a in batch:
                    tag = {
                        "new_folder": "[NEUER ORDNER]",
                        "new_file": "[NEUE DATEI]  ",
                        "updated_file": "[AKTUALISIERT]",
                    }.get(a.reason, "[UPLOAD]")
                    print(f"  {tag} {a.local_path} -> {a.remote_parent} ({a.details})")

            if dry_run:
                continue

            print(
                f"-> Lade {len(batch)} Element(e) hoch nach {remote_parent} ..."
            )
            proc = subprocess.run(cmd, text=True)
            if proc.returncode != 0:
                errors.append(
                    f"Upload fehlgeschlagen (Exit-Code {proc.returncode}) für Ziel {remote_parent}"
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
        metavar="ORDNER",
        help=(
            "Schließt bestimmte Ordner von der Synchronisation aus. "
            "Mehrfach nutzbar oder kommagetrennt (z. B. `-x Videos -x Projekte/Archiv` "
            "oder `--exclude Videos,node_modules`)."
        ),
    )
    parser.add_argument(
        "--exclude-file",
        type=Path,
        default=DEFAULT_EXCLUDE_FILE,
        help=(
            f"Datei mit auszuschließenden Ordnern (eine Zeile pro Muster, Standard: {DEFAULT_EXCLUDE_FILE})."
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
        "--workers",
        type=int,
        default=2,
        help="Anzahl paralleler Abfragen für Remote-Ordnerlisten (Standard: 2).",
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

    if not os.path.isfile(args.proton_bin) or not os.access(args.proton_bin, os.X_OK):
        print(
            f"FEHLER: proton-drive CLI nicht gefunden oder nicht ausführbar unter: {args.proton_bin}",
            file=sys.stderr,
        )
        return 2

    dokumente_dir = args.dokumente.expanduser()
    zotero_dir = args.zotero.expanduser()
    base_dirs = [dokumente_dir, zotero_dir]

    exclude_patterns = load_exclude_patterns(
        cli_excludes=args.exclude,
        exclude_file=args.exclude_file.expanduser() if args.exclude_file else None,
    )

    stats = SyncStats()
    targets = collect_sync_targets(
        dokumente_dir=dokumente_dir,
        zotero_dir=zotero_dir,
        include_hidden=args.include_hidden,
        stats=stats,
        exclude_patterns=exclude_patterns,
    )

    if args.only:
        targets = [t for t in targets if t[2] == args.only]
        if not targets:
            print(
                f"FEHLER: Kein aktiver Zielordner mit dem Namen '{args.only}' gefunden "
                "(eventuell existiert er nicht oder wurde ausgeschlossen).",
                file=sys.stderr,
            )
            return 2

    mode_label = "TROCKENLAUF (DRY-RUN)" if args.dry_run else "LIVE-SYNCHRONISATION"
    print(f"=== Proton Drive Synchronisation ({mode_label}) ===")
    print(f"Dokumente-Quelle : {dokumente_dir} (nur Unterordner, keine losen Dateien)")
    print(f"Zotero-Quelle    : {zotero_dir}")
    print(f"Cloud-Ziel       : {REMOTE_ROOT}")
    print(f"Konflikt-Modus   : -f {args.file_conflict_strategy} -d merge (keine Löschungen!)")
    if exclude_patterns:
        print(f"Ausschluss-Muster: {', '.join(exclude_patterns)}")

    if stats.ignored_loose_files:
        ignored_names = ", ".join(p.name for p in stats.ignored_loose_files)
        print(
            f"Ignorierte lose Dateien in {dokumente_dir} ({len(stats.ignored_loose_files)}): {ignored_names}"
        )
    print()

    # 1. Top-Level /my-files abfragen
    print(f"Prüfe Cloud-Hauptverzeichnis {REMOTE_ROOT} ...")
    root_entries = list_remote_directory(REMOTE_ROOT, proton_bin=args.proton_bin)
    if root_entries is None:
        print(
            f"FEHLER: Konnte {REMOTE_ROOT} in Proton Drive nicht abfragen. "
            "Bitte prüfe `proton-drive account status`.",
            file=sys.stderr,
        )
        return 1
    stats.folders_checked += 1

    all_actions: List[SyncAction] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        for local_folder, remote_parent, folder_name in targets:
            remote_node = root_entries.get(folder_name)
            remote_folder_path = join_remote_path(remote_parent, folder_name)

            if remote_node is None or remote_node.node_type != "folder":
                print(f"[+] Neuer Top-Level-Ordner: {local_folder} -> {remote_folder_path}")
                folder_actions = plan_new_folder_with_exclusions(
                    local_dir=local_folder,
                    remote_parent=remote_parent,
                    include_hidden=args.include_hidden,
                    exclude_patterns=exclude_patterns,
                    base_dirs=base_dirs,
                    stats=stats,
                )
                all_actions.extend(folder_actions)
            else:
                print(f"[*] Vergleiche Ordner: {local_folder} <-> {remote_folder_path} ...")
                folder_actions = plan_directory_sync(
                    local_dir=local_folder,
                    remote_dir_path=remote_folder_path,
                    include_hidden=args.include_hidden,
                    proton_bin=args.proton_bin,
                    executor=executor,
                    stats=stats,
                    exclude_patterns=exclude_patterns,
                    base_dirs=base_dirs,
                )
                all_actions.extend(folder_actions)

    if stats.excluded_folders:
        print("\nAusgeschlossene Ordner:")
        for folder_path, pattern in stats.excluded_folders:
            print(f"  [-] {folder_path} (Muster: '{pattern}')")

    print()
    print("=== Geplante Aktionen ===")
    print(f"Geprüfte Cloud-Ordner                 : {stats.folders_checked}")
    print(f"Ausgeschlossene Ordner                : {len(stats.excluded_folders)}")
    print(f"Neue Ordner                           : {stats.new_folders}")
    print(f"Neue Einzeldateien                    : {stats.new_files}")
    print(f"Aktualisierte Dateien (PC > Cloud)    : {stats.updated_files}")
    print(f"Übersprungen (Inhalt/SHA-1 identisch) : {stats.skipped_identical}")
    print(f"Übersprungen (Cloud neuer/gleich alt) : {stats.skipped_remote_newer_or_equal}")
    print(f"Ignorierte lose Dateien in Dokumente  : {len(stats.ignored_loose_files)}")
    print()

    if all_actions:
        upload_errors = execute_upload_batches(
            actions=all_actions,
            proton_bin=args.proton_bin,
            conflict_strategy=args.file_conflict_strategy,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )
        stats.errors.extend(upload_errors)
    else:
        print("Alles auf dem neuesten Stand – keine Uploads erforderlich.")

    if stats.errors:
        print("\n=== Warnungen / Fehler ===", file=sys.stderr)
        for err in stats.errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("\nSynchronisation erfolgreich abgeschlossen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
