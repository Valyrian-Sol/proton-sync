#!/usr/bin/env python3
"""Selbsttests für Synchronisations-, Ausschluss- und Sicherheitslogik von sync_proton_drive.py."""

import contextlib
import datetime
import hashlib
import io
import os
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from typing import List
from unittest import mock

import sync_proton_drive as spd
from sync_proton_drive import (
    STAGING_PREFIX,
    RemoteNode,
    ScanPolicy,
    SingleInstanceLock,
    SyncAction,
    SyncStats,
    classify_entry,
    collect_sync_targets,
    escape_remote_segment,
    execute_upload_batches,
    is_excluded_folder,
    is_excluded_path,
    is_zotero_sqlite_in_use,
    join_remote_path,
    load_exclude_patterns,
    parse_iso_timestamp,
    plan_new_folder_with_exclusions,
    run_cli_streaming,
    safe_str,
    should_upload_existing_file,
    validate_proton_binary,
    verify_action_before_execution,
    zotero_db_state,
)


def _member_names(actions: List[SyncAction]) -> List[str]:
    names: List[str] = []
    for a in actions:
        names.extend(m.rel for m in a.members)
    return names


class FakeCli:
    """Ersetzt run_cli_streaming, zeichnet Aufrufe auf und erfasst den Staging-Inhalt."""

    def __init__(self, on_call=None) -> None:
        self.calls: List[List[str]] = []
        self.staged_snapshots: List[List[str]] = []
        self.on_call = on_call

    def __call__(self, cmd, timeout_sec=None):
        cmd = list(cmd)
        self.calls.append(cmd)
        if self.on_call is not None:
            self.on_call(cmd)
        if "upload" in cmd:
            dash = cmd.index("--")
            for local in cmd[dash + 1 : -1]:
                snapshot: List[str] = []
                p = Path(local)
                if p.is_dir():
                    for dirpath, dirnames, filenames in os.walk(p):
                        for f in filenames:
                            snapshot.append(os.path.relpath(os.path.join(dirpath, f), p))
                else:
                    snapshot.append(p.name)
                self.staged_snapshots.append(sorted(snapshot))
        return 0, False


class TestScanAndPlanning(unittest.TestCase):
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

            self.assertEqual([t[2] for t in targets], ["Arbeit", "Projekte", "Zotero"])
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
            for d in (videos, projekte, projekte_archiv, projekte_aktuell, node_mods, abs_excl):
                d.mkdir(parents=True, exist_ok=True)

            patterns = ["Videos", "Projekte/Archiv", "node_modules", str(abs_excl)]
            base_dirs = [dok, zot]

            self.assertTrue(is_excluded_folder(videos, patterns, base_dirs)[0])
            self.assertFalse(is_excluded_folder(projekte, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(projekte_archiv, patterns, base_dirs)[0])
            self.assertFalse(is_excluded_folder(projekte_aktuell, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(node_mods, patterns, base_dirs)[0])
            self.assertTrue(is_excluded_folder(abs_excl, patterns, base_dirs)[0])

            stats = SyncStats()
            targets = collect_sync_targets(
                dok, zot, include_hidden=False, stats=stats, exclude_patterns=patterns
            )
            self.assertEqual([t[2] for t in targets], ["Projekte", "Zotero"])
            self.assertEqual(len(stats.excluded_folders), 2)

    def test_exclusion_ignores_case_and_unicode_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok = Path(tmp) / "Dokumente"
            tresor = dok / "Tresor"
            tresor.mkdir(parents=True)
            kdbx = tresor / "Passwoerter.KDBX"
            kdbx.write_text("x", encoding="utf-8")
            nfc_dir = tresor / unicodedata.normalize("NFC", "Bücher")
            nfc_dir.mkdir()

            nfd_pattern = unicodedata.normalize("NFD", "bücher")
            self.assertTrue(is_excluded_path(kdbx, ["*.kdbx"], [dok])[0])
            self.assertTrue(is_excluded_path(nfc_dir, [nfd_pattern], [dok])[0])
            self.assertTrue(is_excluded_path(nfc_dir, ["TRESOR/BÜCHER"], [dok])[0])

    def test_plan_new_folder_filters_excluded_subfolder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok = Path(tmp) / "Dokumente"
            projekt = dok / "Projekt"
            (projekt / "src").mkdir(parents=True)
            (projekt / "src" / "main.py").write_text("print(1)", encoding="utf-8")
            verboten = projekt / "node_modules"
            verboten.mkdir()
            (verboten / "paket.js").write_text("x", encoding="utf-8")
            (projekt / "README.md").write_text("Hallo", encoding="utf-8")

            stats = SyncStats()
            actions = plan_new_folder_with_exclusions(
                local_dir=projekt,
                remote_parent="/my-files",
                policy=ScanPolicy(exclude_patterns=["node_modules"], base_dirs=[dok]),
                stats=stats,
            )

            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].reason, "new_tree")
            names = _member_names(actions)
            self.assertIn("README.md", names)
            self.assertIn("src", names)
            self.assertIn("src/main.py", names)
            self.assertFalse(any("node_modules" in n for n in names))
            self.assertEqual(stats.excluded_folders[0][0], verboten)

    def test_new_folder_never_includes_hidden_symlinks_or_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok = Path(tmp) / "Dokumente"
            projekt = dok / "App"
            projekt.mkdir(parents=True)
            (projekt / "main.py").write_text("print(1)", encoding="utf-8")
            (projekt / ".env").write_text("API_SECRET=geheim", encoding="utf-8")
            outside = Path(tmp) / "id_ed25519"
            outside.write_text("PRIVATE KEY", encoding="utf-8")
            (projekt / "link_to_secret").symlink_to(outside)
            os.link(outside, projekt / "harmlos.txt")

            stats = SyncStats()
            actions = plan_new_folder_with_exclusions(
                local_dir=projekt,
                remote_parent="/my-files",
                policy=ScanPolicy(base_dirs=[dok]),
                stats=stats,
            )
            names = _member_names(actions)
            self.assertEqual(names, ["main.py"])
            self.assertEqual(stats.skipped_symlinks, 1)
            self.assertTrue(any("Hardlink" in w for w in stats.warnings))

            # Mit --allow-hardlinks wird der Hardlink bewusst einbezogen
            stats2 = SyncStats()
            actions2 = plan_new_folder_with_exclusions(
                projekt, "/my-files", ScanPolicy(base_dirs=[dok], allow_hardlinks=True), stats2
            )
            self.assertIn("harmlos.txt", _member_names(actions2))

    def test_other_filesystem_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sub = Path(tmp) / "mount"
            sub.mkdir()
            real_dev = os.lstat(sub).st_dev
            stats = SyncStats()
            policy = ScanPolicy(allowed_devs=frozenset({real_dev + 1}))
            self.assertIsNone(classify_entry(sub, policy, stats))
            self.assertTrue(any("Mount-Point" in w for w in stats.warnings))

            policy_ok = ScanPolicy(allowed_devs=frozenset({real_dev}))
            self.assertEqual(classify_entry(sub, policy_ok, SyncStats())[0], "dir")

    def test_exclude_individual_files_and_symlinked_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dok = root / "Dokumente"
            real_zot = root / "ssd_zotero_data"
            symlink_zot = root / "Zotero"
            dok.mkdir()
            real_zot.mkdir()
            (real_zot / "locate").mkdir()
            symlink_zot.symlink_to(real_zot)
            projekt = dok / "Tresor"
            projekt.mkdir()
            (projekt / "notiz.txt").write_text("ok", encoding="utf-8")
            (projekt / "passwoerter.kdbx").write_text("secret", encoding="utf-8")

            patterns = ["*.kdbx", "Zotero/locate"]
            base_dirs = [dok, symlink_zot]
            self.assertTrue(is_excluded_path(real_zot / "locate", patterns, base_dirs)[0])

            stats = SyncStats()
            targets = collect_sync_targets(
                dok, symlink_zot, include_hidden=False, stats=stats, exclude_patterns=patterns
            )
            self.assertIn("Zotero", [t[2] for t in targets])

            actions = plan_new_folder_with_exclusions(
                projekt, "/my-files", ScanPolicy(exclude_patterns=patterns, base_dirs=base_dirs), stats
            )
            names = _member_names(actions)
            self.assertIn("notiz.txt", names)
            self.assertNotIn("passwoerter.kdbx", names)
            self.assertEqual(len(stats.excluded_files), 1)

    def test_load_exclude_patterns_fail_closed_and_escaped_comma(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ex_file = Path(tmp) / "exclude.txt"
            ex_file.write_text("# Kommentar\nVideos\n\nProjekte/Alt\n", encoding="utf-8")
            patterns = load_exclude_patterns(
                cli_excludes=[r"node_modules, __pycache__,Ordner\,MitKomma", "Videos"],
                exclude_file=ex_file,
                default_excludes=["Temp"],
            )
            self.assertEqual(
                patterns,
                ["Temp", "Videos", "Projekte/Alt", "node_modules", "__pycache__", "Ordner,MitKomma"],
            )
            with self.assertRaises(FileNotFoundError):
                load_exclude_patterns(exclude_file=Path(tmp) / "fehlt.txt", require_exclude_file=True)
            as_dir = Path(tmp) / "ordner_statt_datei"
            as_dir.mkdir()
            with self.assertRaises(IsADirectoryError):
                load_exclude_patterns(exclude_file=as_dir)


class TestUploadDecision(unittest.TestCase):
    def _file_with_remote(self, tmp: str, delta: datetime.timedelta, **kwargs):
        f = Path(tmp) / "notiz.txt"
        f.write_text("PC-Version", encoding="utf-8")
        local_mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime, tz=datetime.timezone.utc)
        node = RemoteNode(name="notiz.txt", node_type="file", claimed_mtime=local_mtime + delta, **kwargs)
        return f, node

    def test_should_upload_when_local_is_newer_and_different(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f, node = self._file_with_remote(
                tmp, -datetime.timedelta(hours=1), claimed_size=10, claimed_sha1="0" * 40
            )
            upload, category, _ = should_upload_existing_file(f, node)
            self.assertTrue(upload)
            self.assertEqual(category, "updated_file")

    def test_should_not_upload_when_cloud_is_newer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f, node = self._file_with_remote(
                tmp, datetime.timedelta(minutes=2), claimed_size=999, claimed_sha1="f" * 40
            )
            upload, category, _ = should_upload_existing_file(f, node)
            self.assertFalse(upload)
            self.assertEqual(category, "remote_newer_or_equal")

    def test_future_claimed_mtime_falls_back_to_server_mtime_and_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "wichtig.txt"
            f.write_text("Aktuelle lokale Daten", encoding="utf-8")
            local_mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime, tz=datetime.timezone.utc)
            node = RemoteNode(
                name="wichtig.txt",
                node_type="file",
                modification_time=local_mtime - datetime.timedelta(hours=2),
                claimed_mtime=local_mtime + datetime.timedelta(days=3650),
                claimed_size=5,
                claimed_sha1="a" * 40,
            )
            warnings: List[str] = []
            upload, category, _ = should_upload_existing_file(f, node, warnings_out=warnings)
            self.assertTrue(upload)
            self.assertEqual(category, "updated_file")
            self.assertIn("Zukunfts-Zeitstempel", warnings[0])

    def test_should_not_upload_when_sha1_matches_even_if_local_mtime_newer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "identisch.txt"
            data = b"Gleicher Dateiinhalt"
            f.write_bytes(data)
            local_mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime, tz=datetime.timezone.utc)
            node = RemoteNode(
                name="identisch.txt",
                node_type="file",
                claimed_mtime=local_mtime - datetime.timedelta(minutes=30),
                claimed_size=len(data),
                claimed_sha1=hashlib.sha1(data).hexdigest(),
            )
            upload, category, _ = should_upload_existing_file(f, node)
            self.assertFalse(upload)
            self.assertEqual(category, "identical")


class TestRemotePaths(unittest.TestCase):
    def test_remote_path_escaping_and_traversal_defense(self) -> None:
        self.assertEqual(escape_remote_segment("a/b"), r"a\/b")
        self.assertEqual(join_remote_path("/my-files", "Projekte"), "/my-files/Projekte")
        self.assertEqual(join_remote_path("/my-files/Projekte/", "Aktuell"), "/my-files/Projekte/Aktuell")
        parent_with_slash = join_remote_path("/my-files", "foo/")
        self.assertEqual(parent_with_slash, r"/my-files/foo\/")
        self.assertEqual(join_remote_path(parent_with_slash, "bar"), r"/my-files/foo\//bar")

        for unsafe_name in ("", ".", "..", "ordner\\", "foo\\bar"):
            with self.assertRaises(ValueError):
                join_remote_path("/my-files", unsafe_name)
        with self.assertRaises(ValueError):
            join_remote_path("/shared-with-me", "Test")
        self.assertIsNotNone(parse_iso_timestamp("2026-02-04T22:23:39.807Z"))


class TestExecution(unittest.TestCase):
    def _make_tree(self, tmp: str):
        dok = Path(tmp).resolve() / "Dokumente"
        projekt = dok / "-f"
        (projekt / "sub").mkdir(parents=True)
        (projekt / "bericht.txt").write_text("inhalt", encoding="utf-8")
        (projekt / "sub" / "daten.csv").write_text("1,2", encoding="utf-8")
        return dok, projekt

    def test_new_tree_uploads_only_from_private_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok, projekt = self._make_tree(tmp)
            actions = plan_new_folder_with_exclusions(
                projekt, "/my-files", ScanPolicy(base_dirs=[dok]), SyncStats()
            )

            # Angriff: Während des Uploads wird eine .env in den echten Ordner geschmuggelt
            def inject(cmd):
                (projekt / ".env").write_text("SECRET", encoding="utf-8")

            fake = FakeCli(on_call=inject)
            with mock.patch.object(spd, "run_cli_streaming", fake), contextlib.redirect_stdout(io.StringIO()):
                errs = execute_upload_batches(actions, "/usr/bin/proton-drive", allowed_roots=[dok])

            self.assertEqual(errs, [])
            self.assertEqual(len(fake.calls), 1)
            cmd = fake.calls[0]
            dash = cmd.index("--")
            staged_path = Path(cmd[dash + 1])
            self.assertIn(STAGING_PREFIX, str(staged_path))
            self.assertEqual(staged_path.name, "-f")
            self.assertEqual(cmd[-1], "/my-files")
            self.assertEqual(fake.staged_snapshots[0], ["bericht.txt", os.path.join("sub", "daten.csv")])

            # Staging wurde vollständig entfernt, Originale sind unversehrt
            self.assertEqual(list(dok.glob(STAGING_PREFIX + "*")), [])
            self.assertEqual((projekt / "bericht.txt").read_text(encoding="utf-8"), "inhalt")
            self.assertEqual(os.lstat(projekt / "bericht.txt").st_nlink, 1)

    def test_toctou_swap_after_scan_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok, projekt = self._make_tree(tmp)
            target = projekt / "bericht.txt"
            st = os.lstat(target)
            action = SyncAction(
                local_path=target,
                remote_parent="/my-files/-f",
                reason="new_file",
                dev=st.st_dev,
                ino=st.st_ino,
            )
            secret = Path(tmp).resolve() / "id_ed25519"
            secret.write_text("PRIVATE KEY", encoding="utf-8")
            target.unlink()
            target.symlink_to(secret)

            ok, err = verify_action_before_execution(action, allowed_roots=[dok])
            self.assertFalse(ok)
            self.assertIn("Symlink", err)

            # Austausch gegen eine andere reguläre Datei wird per Inode erkannt
            target.unlink()
            target.write_text("anderer Inhalt", encoding="utf-8")
            fake = FakeCli()
            with mock.patch.object(spd, "run_cli_streaming", fake), contextlib.redirect_stdout(io.StringIO()):
                errs = execute_upload_batches([action], "/usr/bin/proton-drive", allowed_roots=[dok])
            self.assertEqual(fake.calls, [])
            self.assertTrue(any("ersetzt" in e for e in errs))

    def test_fallback_without_staging_uses_double_dash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dok, projekt = self._make_tree(tmp)
            actions = plan_new_folder_with_exclusions(
                projekt, "/my-files", ScanPolicy(base_dirs=[dok]), SyncStats()
            )
            fake = FakeCli()
            with mock.patch.object(spd, "run_cli_streaming", fake), contextlib.redirect_stdout(io.StringIO()):
                errs = execute_upload_batches(
                    actions, "/usr/bin/proton-drive", allowed_roots=[dok], use_staging=False
                )
            self.assertEqual(errs, [])
            self.assertEqual(
                fake.calls[0],
                ["/usr/bin/proton-drive", "filesystem", "create-folder", "--", "/my-files", "-f"],
            )
            self.assertEqual(
                fake.calls[1],
                ["/usr/bin/proton-drive", "filesystem", "create-folder", "--", "/my-files/-f", "sub"],
            )
            upload_cmds = [c for c in fake.calls if "upload" in c]
            self.assertEqual(len(upload_cmds), 2)
            for c in upload_cmds:
                self.assertIn("--", c)

    def test_replace_strategy_requires_allow_trash(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = spd.main(["--file-conflict-strategy", "replace", "--dry-run"])
        self.assertEqual(rc, 2)
        self.assertIn("--allow-trash", err.getvalue())

    def test_symlinked_zotero_new_tree_uses_logical_remote_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real_zot = Path(tmp).resolve() / "ssd_zotero_profile"
            real_zot.mkdir()
            (real_zot / "paper.pdf").write_text("pdf", encoding="utf-8")

            actions = plan_new_folder_with_exclusions(
                local_dir=real_zot,
                remote_parent="/my-files",
                policy=ScanPolicy(base_dirs=[real_zot]),
                stats=SyncStats(),
                remote_name="Zotero",
            )
            fake = FakeCli()
            with mock.patch.object(spd, "run_cli_streaming", fake), contextlib.redirect_stdout(io.StringIO()):
                errs = execute_upload_batches(actions, "/usr/bin/proton-drive", allowed_roots=[real_zot])
            self.assertEqual(errs, [])
            dash = fake.calls[0].index("--")
            self.assertEqual(Path(fake.calls[0][dash + 1]).name, "Zotero")


class TestHardening(unittest.TestCase):
    def test_terminal_escape_and_bidi_sanitization(self) -> None:
        cleaned = safe_str("harmlos\r\x1b[2K\u202etxt.yek")
        for bad in ("\x1b", "\r", "\u202e"):
            self.assertNotIn(bad, cleaned)
        self.assertIn("\\x1b", cleaned)
        self.assertIn("\\u202e", cleaned)

    def test_cli_output_is_sanitized_and_timeout_kills(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc, timed_out = run_cli_streaming(
                [sys.executable, "-c", "import sys; sys.stdout.write('vorher\\x1b[2Knachher\\n')"]
            )
        self.assertEqual((rc, timed_out), (0, False))
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("\\x1b", out.getvalue())

        with contextlib.redirect_stdout(io.StringIO()):
            _, timed_out = run_cli_streaming(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout_sec=1
            )
        self.assertTrue(timed_out)

    def test_default_binary_never_uses_path_lookup(self) -> None:
        with mock.patch.object(spd.os.path, "isfile", return_value=False), mock.patch.dict(
            os.environ, {"PATH": "/tmp/evil"}
        ):
            self.assertEqual(spd._default_proton_drive_bin(), "/usr/bin/proton-drive")

    def test_validate_proton_binary_rejects_world_writable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
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

    def test_zotero_db_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            zot = Path(tmp) / "Zotero"
            zot.mkdir()
            (zot / "zotero.sqlite").write_text("db", encoding="utf-8")
            with mock.patch.object(spd, "_zotero_process_running", return_value=False):
                self.assertIsNone(zotero_db_state(zot))
                self.assertFalse(is_zotero_sqlite_in_use(zot))
                (zot / "zotero.sqlite-wal").write_text("wal", encoding="utf-8")
                self.assertIn("verwaiste", zotero_db_state(zot))
            with mock.patch.object(spd, "_zotero_process_running", return_value=True):
                self.assertEqual(zotero_db_state(zot), "Zotero läuft gerade")

    def test_single_instance_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp) / "run"
            runtime_dir.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime_dir)}):
                with SingleInstanceLock(enabled=True):
                    with self.assertRaises(RuntimeError):
                        with SingleInstanceLock(enabled=True):
                            pass


if __name__ == "__main__":
    unittest.main()
