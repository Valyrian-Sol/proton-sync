#!/usr/bin/env python3
"""Selbsttests für die Synchronisations- und Ausschlusslogik von sync_proton_drive.py."""

import datetime
import hashlib
import tempfile
import unittest
from pathlib import Path

from sync_proton_drive import (
    RemoteNode,
    SyncStats,
    collect_sync_targets,
    escape_remote_segment,
    has_excluded_descendant,
    is_excluded_folder,
    join_remote_path,
    load_exclude_patterns,
    parse_iso_timestamp,
    plan_new_folder_with_exclusions,
    should_upload_existing_file,
)


class TestSyncLogic(unittest.TestCase):
    def test_collect_sync_targets_ignores_loose_files_in_dokumente(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dok = root / "Dokumente"
            zot = root / "Zotero"
            dok.mkdir()
            zot.mkdir()

            # Unterordner in Dokumente
            (dok / "Projekte").mkdir()
            (dok / "Arbeit").mkdir()
            (dok / ".hidden_dir").mkdir()

            # Lose Dateien direkt in Dokumente -> müssen ignoriert werden!
            loose1 = dok / "Notiz.txt"
            loose2 = dok / "archive.tar.gz"
            loose1.write_text("inhalt", encoding="utf-8")
            loose2.write_text("inhalt2", encoding="utf-8")

            stats = SyncStats()
            targets = collect_sync_targets(dok, zot, include_hidden=False, stats=stats)

            target_names = [t[2] for t in targets]
            self.assertEqual(target_names, ["Arbeit", "Projekte", "Zotero"])
            self.assertEqual(len(stats.ignored_loose_files), 2)
            self.assertIn(loose1, stats.ignored_loose_files)
            self.assertIn(loose2, stats.ignored_loose_files)

    def test_exclude_folders_by_name_relative_and_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dok = root / "Dokumente"
            zot = root / "Zotero"
            dok.mkdir()
            zot.mkdir()

            videos = dok / "Videos"
            projekte = dok / "Projekte"
            projekte_archiv = projekte / "Archiv"
            projekte_aktuell = projekte / "Aktuell"
            node_mods = projekte_aktuell / "node_modules"
            abs_excl = dok / "Privat_Temp"

            for d in (videos, projekte, projekte_archiv, projekte_aktuell, node_mods, abs_excl):
                d.mkdir(parents=True, exist_ok=True)

            patterns = [
                "Videos",
                "Projekte/Archiv",
                "node_modules",
                str(abs_excl),
            ]
            base_dirs = [dok, zot]

            self.assertTrue(is_excluded_folder(videos, patterns, base_dirs)[0])
            self.assertFalse(is_excluded_folder(projekte, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(projekte_archiv, patterns, base_dirs)[0])
            self.assertFalse(is_excluded_folder(projekte_aktuell, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(node_mods, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(abs_excl, patterns, base_dirs)[0])

            # Top-Level-Sammlung schließt "Videos" und "Privat_Temp" direkt aus
            stats = SyncStats()
            targets = collect_sync_targets(
                dok, zot, include_hidden=False, stats=stats, exclude_patterns=patterns
            )
            target_names = [t[2] for t in targets]
            self.assertEqual(target_names, ["Projekte", "Zotero"])
            self.assertEqual(len(stats.excluded_folders), 2)

    def test_plan_new_folder_splits_when_excluded_subfolder_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok = Path(tmp) / "Dokumente"
            projekt = dok / "Projekt"
            erlaubt = projekt / "src"
            verboten = projekt / "node_modules"
            erlaubt.mkdir(parents=True)
            verboten.mkdir(parents=True)
            readme = projekt / "README.md"
            readme.write_text("Hallo", encoding="utf-8")

            patterns = ["node_modules"]
            base_dirs = [dok]
            stats = SyncStats()

            self.assertTrue(
                has_excluded_descendant(
                    projekt, patterns, include_hidden=False, base_dirs=base_dirs
                )
            )

            actions = plan_new_folder_with_exclusions(
                local_dir=projekt,
                remote_parent="/my-files",
                include_hidden=False,
                exclude_patterns=patterns,
                base_dirs=base_dirs,
                stats=stats,
            )

            reasons = [(a.local_path.name, a.reason, a.remote_parent) for a in actions]
            self.assertIn(("Projekt", "create_remote_folder", "/my-files"), reasons)
            self.assertIn(("README.md", "new_file", "/my-files/Projekt"), reasons)
            self.assertIn(("src", "new_folder", "/my-files/Projekt"), reasons)
            # node_modules darf NICHT in den Upload-Aktionen auftauchen
            uploaded_names = [a.local_path.name for a in actions]
            self.assertNotIn("node_modules", uploaded_names)
            self.assertEqual(len(stats.excluded_folders), 1)
            self.assertEqual(stats.excluded_folders[0][0], verboten)

    def test_load_exclude_patterns_from_file_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ex_file = Path(tmp) / "exclude.txt"
            ex_file.write_text(
                "# Kommentar\nVideos\n\nProjekte/Alt\n", encoding="utf-8"
            )
            patterns = load_exclude_patterns(
                cli_excludes=["node_modules, __pycache__", "Videos"],
                exclude_file=ex_file,
                default_excludes=["Temp"],
            )
            self.assertEqual(
                patterns,
                ["Temp", "Videos", "Projekte/Alt", "node_modules", "__pycache__"],
            )

    def test_should_upload_when_local_is_newer_and_different(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "notiz.txt"
            f.write_text("Neue PC-Version", encoding="utf-8")

            local_mtime = datetime.datetime.fromtimestamp(
                f.stat().st_mtime, tz=datetime.timezone.utc
            )
            remote_mtime = local_mtime - datetime.timedelta(hours=1)

            remote_node = RemoteNode(
                name="notiz.txt",
                node_type="file",
                claimed_mtime=remote_mtime,
                claimed_size=10,
                claimed_sha1="0" * 40,
            )

            upload, category, _ = should_upload_existing_file(f, remote_node)
            self.assertTrue(upload)
            self.assertEqual(category, "updated_file")

    def test_should_not_upload_when_cloud_is_newer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "notiz.txt"
            f.write_text("Alte PC-Version", encoding="utf-8")

            local_mtime = datetime.datetime.fromtimestamp(
                f.stat().st_mtime, tz=datetime.timezone.utc
            )
            remote_mtime = local_mtime + datetime.timedelta(hours=2)

            remote_node = RemoteNode(
                name="notiz.txt",
                node_type="file",
                claimed_mtime=remote_mtime,
                claimed_size=999,
                claimed_sha1="f" * 40,
            )

            upload, category, _ = should_upload_existing_file(f, remote_node)
            self.assertFalse(upload)
            self.assertEqual(category, "remote_newer_or_equal")

    def test_should_not_upload_when_sha1_matches_even_if_local_mtime_newer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "identisch.txt"
            data = b"Gleicher Dateiinhalt"
            f.write_bytes(data)
            sha1 = hashlib.sha1(data).hexdigest()

            local_mtime = datetime.datetime.fromtimestamp(
                f.stat().st_mtime, tz=datetime.timezone.utc
            )
            remote_mtime = local_mtime - datetime.timedelta(minutes=30)

            remote_node = RemoteNode(
                name="identisch.txt",
                node_type="file",
                claimed_mtime=remote_mtime,
                claimed_size=len(data),
                claimed_sha1=sha1,
            )

            upload, category, _ = should_upload_existing_file(f, remote_node)
            self.assertFalse(upload)
            self.assertEqual(category, "identical")

    def test_remote_path_escaping(self) -> None:
        self.assertEqual(escape_remote_segment("a/b"), r"a\/b")
        self.assertEqual(join_remote_path("/my-files", "Projekte"), "/my-files/Projekte")
        self.assertEqual(join_remote_path("/my-files/Projekte/", "Aktuell"), "/my-files/Projekte/Aktuell")
        dt = parse_iso_timestamp("2026-02-04T22:23:39.807Z")
        self.assertIsNotNone(dt)


if __name__ == "__main__":
    unittest.main()
