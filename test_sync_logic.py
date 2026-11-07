#!/usr/bin/env python3
"""Selbsttests für Synchronisations-, Ausschluss- und Sicherheitslogik von sync_proton_drive.py."""

import datetime
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sync_proton_drive import (
    RemoteNode,
    SingleInstanceLock,
    SyncAction,
    SyncStats,
    collect_sync_targets,
    escape_remote_segment,
    execute_upload_batches,
    has_excluded_descendant,
    is_excluded_folder,
    is_excluded_path,
    is_zotero_sqlite_in_use,
    join_remote_path,
    load_exclude_patterns,
    parse_iso_timestamp,
    plan_new_folder_with_exclusions,
    safe_str,
    should_upload_existing_file,
    validate_proton_binary,
    verify_action_before_execution,
)


class TestSyncLogic(unittest.TestCase):
    def test_collect_sync_targets_ignores_loose_files_in_dokumente(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dok = root / "Dokumente"
            zot = root / "Zotero"
            dok.mkdir()
            zot.mkdir()

            (dok / "Projekte").mkdir()
            (dok / "Arbeit").mkdir()
            (dok / ".hidden_dir").mkdir()

            loose1 = dok / "Notiz.txt"
            loose2 = dok / "archive.tar.gz"
            loose1.write_text("inhalt", encoding="utf-8")
            loose2.write_text("inhalt2", encoding="utf-8")

            stats = SyncStats()
            targets = collect_sync_targets(dok, zot, include_hidden=False, stats=stats)

            target_names = [t[2] for t in targets]
            self.assertEqual(target_names, ["Arbeit", "Projekte", "Zotero"])
            self.assertEqual(len(stats.ignored_loose_files), 2)
            self.assertIn(loose1.resolve(), stats.ignored_loose_files)
            self.assertIn(loose2.resolve(), stats.ignored_loose_files)

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

            for d in (
                videos,
                projekte,
                projekte_archiv,
                projekte_aktuell,
                node_mods,
                abs_excl,
            ):
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
            self.assertFalse(
                is_excluded_folder(projekte_aktuell, patterns, base_dirs)[0]
            )
            self.assertTrue(is_excluded_folder(node_mods, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(abs_excl, patterns, base_dirs)[0])

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
            uploaded_names = [a.local_path.name for a in actions]
            self.assertNotIn("node_modules", uploaded_names)
            self.assertEqual(len(stats.excluded_folders), 1)
            self.assertEqual(stats.excluded_folders[0][0], verboten)

    def test_new_folder_never_leaks_hidden_files_or_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok = Path(tmp) / "Dokumente"
            projekt = dok / "App"
            projekt.mkdir(parents=True)
            (projekt / "main.py").write_text("print(1)", encoding="utf-8")
            (projekt / ".env").write_text("API_SECRET=geheim", encoding="utf-8")

            outside = Path(tmp) / "outside_secret.txt"
            outside.write_text("private_key", encoding="utf-8")
            (projekt / "link_to_secret").symlink_to(outside)

            stats = SyncStats()
            actions = plan_new_folder_with_exclusions(
                local_dir=projekt,
                remote_parent="/my-files",
                include_hidden=False,
                exclude_patterns=[],
                base_dirs=[dok],
                stats=stats,
            )

            # Darf NICHT als monolithisches `new_folder` hochgeladen werden!
            reasons = [(a.local_path.name, a.reason) for a in actions]
            self.assertIn(("App", "create_remote_folder"), reasons)
            self.assertIn(("main.py", "new_file"), reasons)
            self.assertNotIn((".env", "new_file"), reasons)
            self.assertNotIn(("link_to_secret", "new_file"), reasons)
            self.assertNotIn(("App", "new_folder"), reasons)

    def test_has_excluded_descendant_catches_hidden_excluded_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            projekt = Path(tmp) / "Repo"
            (projekt / ".git").mkdir(parents=True)
            self.assertTrue(
                has_excluded_descendant(
                    projekt,
                    exclude_patterns=[".git"],
                    include_hidden=False,
                    base_dirs=[Path(tmp)],
                )
            )

    def test_exclude_individual_files_and_symlinked_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dok = root / "Dokumente"
            real_zot = root / "ssd_zotero_data"
            symlink_zot = root / "Zotero"
            dok.mkdir()
            real_zot.mkdir()
            (real_zot / "locate").mkdir()
            (real_zot / "storage").mkdir()
            symlink_zot.symlink_to(real_zot)

            projekt = dok / "Tresor"
            projekt.mkdir()
            keep = projekt / "notiz.txt"
            secret_db = projekt / "passwoerter.kdbx"
            keep.write_text("ok", encoding="utf-8")
            secret_db.write_text("secret", encoding="utf-8")

            patterns = ["*.kdbx", "Zotero/locate"]
            base_dirs = [dok, symlink_zot]

            self.assertTrue(is_excluded_path(secret_db, patterns, base_dirs)[0])
            self.assertTrue(
                is_excluded_path(real_zot / "locate", patterns, base_dirs)[0]
            )

            stats = SyncStats()
            targets = collect_sync_targets(
                dok,
                symlink_zot,
                include_hidden=False,
                stats=stats,
                exclude_patterns=patterns,
            )
            # Symlink ~/Zotero behält den Cloud-Zielnamen "Zotero" statt "ssd_zotero_data"
            self.assertIn("Zotero", [t[2] for t in targets])

            actions = plan_new_folder_with_exclusions(
                local_dir=projekt,
                remote_parent="/my-files",
                include_hidden=False,
                exclude_patterns=patterns,
                base_dirs=base_dirs,
                stats=stats,
            )
            uploaded = [a.local_path.name for a in actions]
            self.assertIn("notiz.txt", uploaded)
            self.assertNotIn("passwoerter.kdbx", uploaded)
            self.assertEqual(len(stats.excluded_files), 1)

    def test_load_exclude_patterns_fail_closed_and_escaped_comma(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ex_file = Path(tmp) / "exclude.txt"
            ex_file.write_text(
                "# Kommentar\nVideos\n\nProjekte/Alt\n", encoding="utf-8"
            )
            patterns = load_exclude_patterns(
                cli_excludes=[r"node_modules, __pycache__,Ordner\,MitKomma", "Videos"],
                exclude_file=ex_file,
                default_excludes=["Temp"],
            )
            self.assertEqual(
                patterns,
                [
                    "Temp",
                    "Videos",
                    "Projekte/Alt",
                    "node_modules",
                    "__pycache__",
                    "Ordner,MitKomma",
                ],
            )

            # Explizit angeforderte, aber fehlende Exclude-Datei MUSS Fehler werfen (Fail-Closed)
            missing = Path(tmp) / "gibts_nicht.txt"
            with self.assertRaises(FileNotFoundError):
                load_exclude_patterns(exclude_file=missing, require_exclude_file=True)

            # Verzeichnis statt Datei MUSS Fehler werfen
            as_dir = Path(tmp) / "ordner_statt_datei"
            as_dir.mkdir()
            with self.assertRaises(IsADirectoryError):
                load_exclude_patterns(exclude_file=as_dir, require_exclude_file=False)

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
            remote_mtime = local_mtime + datetime.timedelta(minutes=2)

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

    def test_future_claimed_mtime_falls_back_to_server_mtime_and_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "wichtig.txt"
            f.write_text("Aktuelle lokale Daten", encoding="utf-8")

            local_mtime = datetime.datetime.fromtimestamp(
                f.stat().st_mtime, tz=datetime.timezone.utc
            )
            spoofed_future = local_mtime + datetime.timedelta(days=3650)
            sane_server_mtime = local_mtime - datetime.timedelta(hours=2)

            remote_node = RemoteNode(
                name="wichtig.txt",
                node_type="file",
                modification_time=sane_server_mtime,
                claimed_mtime=spoofed_future,
                claimed_size=5,
                claimed_sha1="a" * 40,
            )

            warnings: list[str] = []
            upload, category, _ = should_upload_existing_file(
                f, remote_node, warnings_out=warnings
            )
            self.assertTrue(upload)
            self.assertEqual(category, "updated_file")
            self.assertEqual(len(warnings), 1)
            self.assertIn("Zukunfts-Zeitstempel", warnings[0])

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

    def test_remote_path_escaping_and_traversal_defense(self) -> None:
        self.assertEqual(escape_remote_segment("a/b"), r"a\/b")
        self.assertEqual(
            join_remote_path("/my-files", "Projekte"), "/my-files/Projekte"
        )
        self.assertEqual(
            join_remote_path("/my-files/Projekte/", "Aktuell"),
            "/my-files/Projekte/Aktuell",
        )
        # Maskierter Slash am Ende von parent darf nicht abgeschnitten werden
        parent_with_slash = join_remote_path("/my-files", "foo/")
        self.assertEqual(parent_with_slash, r"/my-files/foo\/")
        self.assertEqual(
            join_remote_path(parent_with_slash, "bar"), r"/my-files/foo\//bar"
        )

        # Unsichere Knotennamen und Ausbruch aus /my-files müssen verweigert werden
        for unsafe_name in ("", ".", "..", "ordner\\"):
            with self.assertRaises(ValueError):
                join_remote_path("/my-files", unsafe_name)
        with self.assertRaises(ValueError):
            join_remote_path("/shared-with-me", "Test")

        dt = parse_iso_timestamp("2026-02-04T22:23:39.807Z")
        self.assertIsNotNone(dt)

    def test_toctou_symlink_swap_and_cli_double_dash_protection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok = Path(tmp).resolve() / "Dokumente"
            projekt = dok / "-f"
            projekt.mkdir(parents=True)
            legit_file = projekt / "bericht.txt"
            legit_file.write_text("inhalt", encoding="utf-8")

            # 1. Reguläre Aktion prüfen + `--` Trennung bei subprocess.run verifizieren
            mkdir_act = SyncAction(
                local_path=projekt,
                remote_parent="/my-files",
                reason="create_remote_folder",
            )
            upload_act = SyncAction(
                local_path=legit_file,
                remote_parent="/my-files/-f",
                reason="new_file",
            )

            recorded_cmds: list[list[str]] = []

            def fake_run(cmd, **kwargs):
                recorded_cmds.append(list(cmd))
                res = mock.Mock()
                res.returncode = 0
                return res

            with mock.patch("sync_proton_drive.subprocess.run", side_effect=fake_run):
                errs = execute_upload_batches(
                    actions=[mkdir_act, upload_act],
                    proton_bin="/usr/bin/proton-drive",
                    allowed_roots=[dok],
                    base_dirs=[dok],
                )
            self.assertEqual(errs, [])
            self.assertEqual(
                recorded_cmds[0],
                [
                    "/usr/bin/proton-drive",
                    "filesystem",
                    "create-folder",
                    "--",
                    "/my-files",
                    "-f",
                ],
            )
            self.assertIn("--", recorded_cmds[1])
            dash_idx = recorded_cmds[1].index("--")
            self.assertEqual(recorded_cmds[1][dash_idx + 1], str(legit_file))

            # 2. TOCTOU-Angriff: Datei wird vor Ausführung durch Symlink ersetzt
            secret = Path(tmp).resolve() / "id_ed25519"
            secret.write_text("PRIVATE KEY", encoding="utf-8")
            legit_file.unlink()
            legit_file.symlink_to(secret)

            ok, err = verify_action_before_execution(
                upload_act, allowed_roots=[dok], base_dirs=[dok]
            )
            self.assertFalse(ok)
            self.assertIn("Symlink", err)

    def test_terminal_escape_and_bidi_sanitization(self) -> None:
        evil_name = "harmlos\r\x1b[2K\u202etxt.yek"
        cleaned = safe_str(evil_name)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\r", cleaned)
        self.assertNotIn("\u202e", cleaned)
        self.assertIn("\\x1b", cleaned)
        self.assertIn("\\u202e", cleaned)

    def test_validate_proton_binary_rejects_world_writable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Sicheres privates Verzeichnis, aber Binary world-writable (0o777)
            os.chmod(tmp, 0o700)
            fake_bin = Path(tmp) / "proton-drive"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(fake_bin, 0o777)

            ok, _, err = validate_proton_binary(str(fake_bin))
            self.assertFalse(ok)
            self.assertIn("world-writable", err)

            os.chmod(fake_bin, 0o700)
            ok2, resolved, _ = validate_proton_binary(str(fake_bin))
            self.assertTrue(ok2)
            self.assertEqual(resolved, str(fake_bin.resolve()))

    def test_zotero_sqlite_lock_detection_and_single_instance_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            zot = Path(tmp) / "Zotero"
            zot.mkdir()
            (zot / "zotero.sqlite").write_text("db", encoding="utf-8")
            self.assertFalse(is_zotero_sqlite_in_use(zot))

            (zot / "zotero.sqlite-wal").write_text("wal", encoding="utf-8")
            self.assertTrue(is_zotero_sqlite_in_use(zot))

            # SingleInstanceLock verhindert zweiten parallelen Lauf
            runtime_dir = Path(tmp) / "run"
            runtime_dir.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_dir)}):
                with SingleInstanceLock(enabled=True):
                    with self.assertRaises(RuntimeError):
                        with SingleInstanceLock(enabled=True):
                            pass


if __name__ == "__main__":
    unittest.main()
