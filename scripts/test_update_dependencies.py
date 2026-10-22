#!/usr/bin/env python3
"""更新器のGo指定同期・検証失敗時の無変更・反映時の競合検出を隔離して確認する。"""
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('updater', Path(__file__).with_name('update-dependencies.py'))
UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


class UpdateTests(unittest.TestCase):
    def seed(self, root):
        """実ソース・ネットワーク・Go導入に触れない最小構成を作る。"""
        for name in UPDATER.OUTPUT_FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Go1.27.2\n')
        (root / 'go.mod').write_text('module example\n\ngo 1.27.2\n')
        (root / 'mise.toml').write_text('[tools]\ngo = "1.27.2"\n')
        (root / 'scripts/go-dependencies.json').write_text('{}\n')

    def test_all_pins_follow_go(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.seed(root)
            with patch.object(UPDATER, 'run'):
                UPDATER.pin_go(root, '1.28.1')
            for name in UPDATER.PIN_FILES:
                self.assertIn('1.28.1', (root / name).read_text())
                self.assertNotIn('1.27.2', (root / name).read_text())

    def invoke(self, fail=False, conflict=False, apply=True, full=False, unchanged=False):
        """外部コマンドの成功・失敗・作業中の競合を再現し、元ファイルの保護を確認する。"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.seed(root)
            before = {name: (root / name).read_bytes() for name in UPDATER.OUTPUT_FILES}

            calls = []
            version = '1.27.2' if unchanged else '1.28.1'

            def fake_run(args, cwd, **kwargs):
                calls.append(args)
                if args[-1] == '-json':
                    return subprocess.CompletedProcess(args, 0, json.dumps({'Go': version, 'Require': []}).encode())
                if args[-1] in ('scripts/check.sh', 'scripts/check-update.sh'):
                    if fail:
                        raise subprocess.CalledProcessError(1, args)
                    if conflict:
                        (root / 'go.mod').write_text('concurrent user edit\n')
                return subprocess.CompletedProcess(args, 0)

            def stage(work):
                self.seed(work)

            argv = ['--go', version, '--modules', 'none'] + (['--apply'] if apply else []) + (['--full-checks'] if full else [])
            with patch.object(UPDATER, 'ROOT', root), patch.object(UPDATER, 'stage_sources', side_effect=stage), patch.object(UPDATER, 'run', side_effect=fake_run), contextlib.redirect_stdout(io.StringIO()):
                if fail:
                    with self.assertRaises(subprocess.CalledProcessError):
                        UPDATER.main(argv)
                elif conflict:
                    with self.assertRaisesRegex(SystemExit, '元ファイルが変更'):
                        UPDATER.main(argv)
                else:
                    UPDATER.main(argv)
            for name in UPDATER.OUTPUT_FILES:
                if conflict and name == 'go.mod':
                    self.assertEqual((root / name).read_text(), 'concurrent user edit\n')
                elif fail or conflict or not apply or unchanged:
                    self.assertEqual((root / name).read_bytes(), before[name])
            if apply and not fail and not conflict and not unchanged:
                self.assertIn('go 1.28.1', (root / 'go.mod').read_text())
            checks = [args[-1] for args in calls if args[-1] in ('scripts/check.sh', 'scripts/check-update.sh')]
            self.assertEqual(checks, [] if unchanged and not full else ['scripts/check.sh' if full else 'scripts/check-update.sh'])

    def test_failed_verification_keeps_originals(self):
        self.invoke(fail=True)

    def test_concurrent_edit_is_preserved(self):
        self.invoke(conflict=True)

    def test_success_applies_verified_files(self):
        self.invoke()

    def test_preview_keeps_originals(self):
        self.invoke(apply=False)

    def test_full_checks_are_opt_in(self):
        self.invoke(full=True)

    def test_unchanged_update_skips_checks(self):
        self.invoke(unchanged=True)

    def test_explicit_full_checks_run_without_changes(self):
        self.invoke(unchanged=True, full=True)

    def test_full_checks_cannot_be_skipped(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            UPDATER.main(['--full-checks', '--skip-checks'])

    def test_apply_cannot_skip_checks(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            UPDATER.main(['--apply', '--skip-checks'])


if __name__ == '__main__':
    unittest.main()
