"""ホストのDocker/systemdを置き換え、停止順序・バックアップ・失敗時の無変更を検証する。"""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("deployment", Path(__file__).with_name("deploy-software-update.py"))
deployment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deployment)


class DeploymentTests(unittest.TestCase):
    """実データの代わりに一時ファイルを使い、ホストコマンドだけを差し替える。"""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.job = self.root / ("b" * 24)
        self.source = self.job / "source"
        self.source.mkdir(parents=True)
        self.revision = "a" * 40
        self.binary = self.root / "oimobbs"
        self.binary.write_bytes(b"old executable")
        self.binary.chmod(0o750)
        self.config = self.root / "config.json"
        self.config.write_text("{}")
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "saved.txt").write_text("保存済みデータ")
        self.config.write_text(json.dumps({"data_dir": str(self.data)}))
        self.calls = []

    def systemd(self):
        config = {"mode": "systemd", "unit": "oimobbs.service", "binary": str(self.binary), "config": str(self.config), "data_dir": str(self.data), "go_binary": "/usr/local/go/bin/go"}
        return deployment.Systemd(config, self.source, self.revision, self.job)

    def systemd_run(self, args, **kwargs):
        self.calls.append(args)
        if "build" in args:
            Path(args[args.index("-o") + 1]).write_bytes(b"new executable")
        if args[:2] == ["systemctl", "stop"]:
            self.assertEqual(self.binary.read_bytes(), b"old executable")
        if args[:2] == ["systemctl", "start"] and self.binary.read_bytes() == b"new executable":
            self.assertTrue((self.job / "data.tar.gz.sha256").exists())
        return subprocess.CompletedProcess(args, 0)

    def test_systemd_backup_precedes_install_and_health(self):
        backend = self.systemd()
        with patch.object(deployment, "run", self.systemd_run), patch.object(deployment, "output", return_value="inactive"), patch.object(deployment.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            backend.prepare()
            self.assertFalse(any("stop" in call for call in self.calls))
            backend.apply()
        self.assertEqual(self.binary.read_bytes(), b"new executable")
        self.assertEqual((self.job / "oimobbs.before").read_bytes(), b"old executable")
        self.assertEqual(self.binary.stat().st_mode & 0o777, 0o750)
        with tarfile.open(self.job / "data.tar.gz") as archive:
            self.assertEqual(archive.extractfile("./saved.txt").read().decode(), "保存済みデータ")

    def test_systemd_validation_failure_does_not_stop(self):
        with patch.object(deployment, "run", side_effect=subprocess.CalledProcessError(1, ["go", "test"])):
            with self.assertRaises(subprocess.CalledProcessError):
                self.systemd().prepare()
        self.assertEqual(self.binary.read_bytes(), b"old executable")
        self.assertFalse((self.job / "data.tar.gz").exists())

    def test_systemd_changed_binary_rejected_before_stop(self):
        backend = self.systemd()
        with patch.object(deployment, "run", self.systemd_run):
            backend.prepare()
            self.binary.write_bytes(b"operator replaced executable")
            with self.assertRaisesRegex(ValueError, "検証後"):
                backend.apply()
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_systemd_backup_failure_restarts_old_binary(self):
        backend = self.systemd()
        with patch.object(deployment, "run", self.systemd_run), patch.object(deployment, "output", return_value="inactive"):
            backend.prepare()
            with patch.object(backend, "backup", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    backend.apply()
        self.assertEqual(self.binary.read_bytes(), b"old executable")
        self.assertIn(["systemctl", "start", "oimobbs.service"], self.calls)

    def test_systemd_health_failure_is_not_success(self):
        backend = self.systemd()
        with patch.object(deployment, "run", self.systemd_run), patch.object(deployment, "output", return_value="inactive"):
            backend.prepare()
            with patch.object(deployment.time, "monotonic", side_effect=[0, 121]):
                with self.assertRaisesRegex(ValueError, "ヘルスチェック"):
                    backend.apply()
        self.assertEqual(self.binary.read_bytes(), b"new executable")
        self.assertTrue((self.job / "data.tar.gz.sha256").exists())

    def test_systemd_install_failure_before_replacement_restarts_original(self):
        backend = self.systemd()
        with patch.object(deployment, "run", self.systemd_run), patch.object(deployment, "output", return_value="inactive"):
            backend.prepare()
            with patch.object(backend, "install", side_effect=OSError("binary filesystem full")):
                with self.assertRaises(OSError):
                    backend.apply()
        self.assertEqual(self.binary.read_bytes(), b"old executable")
        self.assertIn(["systemctl", "start", "oimobbs.service"], self.calls)

    def docker(self):
        compose = self.root / "compose.yaml"
        compose.write_text("services: {}")
        config = {"mode": "docker", "project_directory": str(self.root), "compose_files": [str(compose)], "service": "bbs", "data_destination": "/data", "override_file": str(self.root / "active-compose.json")}
        self.container = {"Id": "c" * 64, "Image": "sha256:" + "d" * 64, "Config": {"User": "10001:10001", "Cmd": ["validation-serve", "--config", "/etc/oimobbs/config.json"]}, "State": {"Running": True, "Health": {"Status": "healthy"}}, "Mounts": [{"Destination": "/data", "Type": "volume", "Name": "test-data"}]}
        self.old = copy.deepcopy(self.container)
        return deployment.Docker(config, self.source, self.revision, self.job)

    def docker_output(self, args):
        self.calls.append(args)
        if "ps" in args:
            return self.container["Id"]
        if args[:2] == ["docker", "inspect"]:
            return json.dumps([self.container])
        if args[:2] == ["docker", "exec"]:
            return '{"data_dir":"/data/site"}'
        if args[:3] == ["docker", "image", "inspect"]:
            return "sha256:" + "e" * 64
        raise AssertionError(args)

    def docker_run(self, args, **kwargs):
        self.calls.append(args)
        if "stop" in args:
            self.container["State"]["Running"] = False
        if args[:2] == ["docker", "start"]:
            self.container["State"]["Running"] = True
        if args[:2] == ["docker", "run"]:
            self.assertFalse(self.container["State"]["Running"])
            with tarfile.open(fileobj=kwargs["stdout"], mode="w:gz") as archive:
                content = b"durable data"
                member = tarfile.TarInfo("./state.json")
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        if "up" in args:
            self.assertTrue((self.job / "data.tar.gz.sha256").exists())
            self.assertIn("--no-deps", args)
            self.assertIn("--no-build", args)
            self.container["Id"] = "f" * 64
            self.container["Image"] = "sha256:" + "e" * 64
            self.container["State"]["Running"] = True
        return subprocess.CompletedProcess(args, 0)

    def test_docker_backup_precedes_replacement_and_persists_image(self):
        backend = self.docker()
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", self.docker_output):
            backend.prepare()
            self.assertFalse(any("stop" in call for call in self.calls))
            backend.apply()
        self.assertTrue(Path(backend.c["override_file"]).exists())
        self.assertIn(["docker", "image", "tag", self.old["Image"], "oimobbs-update:before-" + self.job.name], self.calls)
        self.assertTrue((self.job / "data.tar.gz.sha256").exists())

    def test_docker_changed_compose_rejected_before_stop(self):
        backend = self.docker()
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", self.docker_output):
            backend.prepare()
            Path(backend.c["compose_files"][0]).write_text("operator edited")
            with self.assertRaisesRegex(ValueError, "Compose"):
                backend.apply()
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_docker_data_outside_backup_is_rejected(self):
        backend = self.docker()
        original_output = self.docker_output
        def outside(args):
            if args[:2] == ["docker", "exec"]:
                return '{"data_dir":"/unprotected/site"}'
            return original_output(args)
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", outside):
            with self.assertRaisesRegex(ValueError, "保存先"):
                backend.prepare()
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_docker_nested_data_mount_is_rejected(self):
        backend = self.docker()
        self.container["Mounts"].append({"Destination":"/data/keys", "Type":"volume", "Name":"separate-keys"})
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", self.docker_output):
            with self.assertRaisesRegex(ValueError, "別のマウント"):
                backend.prepare()

    def test_docker_changed_app_config_is_rejected_before_stop(self):
        backend = self.docker()
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", self.docker_output):
            backend.prepare()
        original_output = self.docker_output
        def changed(args):
            if args[:2] == ["docker", "exec"]:
                return '{"data_dir":"/data/other"}'
            return original_output(args)
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", changed):
            with self.assertRaisesRegex(ValueError, "起動設定"):
                backend.apply()
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_systemd_wrong_backup_directory_is_rejected(self):
        backend = self.systemd()
        backend.c["data_dir"] = str(self.root / "wrong-data")
        with patch.object(deployment, "run", self.systemd_run):
            with self.assertRaisesRegex(ValueError, "保存先"):
                backend.prepare()
        self.assertFalse(any("stop" in call for call in self.calls))

    def test_docker_backup_failure_restarts_existing_container(self):
        backend = self.docker()
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", self.docker_output):
            backend.prepare()
            with patch.object(backend, "backup", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    backend.apply()
        self.assertIn(["docker", "start", self.old["Id"]], self.calls)
        self.assertFalse(any("up" in call for call in self.calls))

    def test_docker_unhealthy_image_is_not_success(self):
        backend = self.docker()
        with patch.object(deployment, "run", self.docker_run), patch.object(deployment, "output", self.docker_output):
            backend.prepare()
            self.container["State"]["Health"]["Status"] = "unhealthy"
            with self.assertRaisesRegex(ValueError, "ヘルスチェック"):
                backend.apply()
        self.assertFalse(Path(backend.c["override_file"]).exists())
        self.assertTrue((self.job / "data.tar.gz.sha256").exists())

    def test_backup_corruption_and_empty_archives_are_rejected(self):
        path = self.root / "broken.tar.gz"
        path.write_bytes(b"not gzip")
        with self.assertRaises((tarfile.TarError, OSError)):
            deployment.verify_archive(path)
        with tarfile.open(path, "w:gz"):
            pass
        with self.assertRaisesRegex(ValueError, "ファイル"):
            deployment.verify_archive(path)

    def test_private_config_rejects_links_and_public_permissions(self):
        path = self.root / "host.json"
        path.write_text("{}")
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            deployment.private_json(path)
        path.chmod(0o600)
        linked = self.root / "linked.json"
        linked.symlink_to(path)
        with self.assertRaises(ValueError):
            deployment.private_json(linked)
        self.assertEqual(deployment.private_json(path), {})

    def test_relative_paths_and_unknown_settings_are_rejected(self):
        with self.assertRaises(ValueError):
            deployment.absolute("relative/path")
        config = self.root / "host.json"
        config.write_text('{"mode":"systemd","command":"bad"}')
        config.chmod(0o600)
        with self.assertRaises(ValueError):
            deployment.load_config(config)


if __name__ == "__main__":
    unittest.main()
