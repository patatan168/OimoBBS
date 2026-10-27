#!/usr/bin/env python3
"""ホストの固定設定に従い、Docker/systemdの検証・停止・バックアップ・更新を行う。"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time


def run(args, **kwargs):
    """シェルを介さず固定のコマンドと引数を実行する。"""
    print("実行:", args[0], args[1] if len(args) > 1 else "", flush=True)
    return subprocess.run(args, check=True, **kwargs)


def output(args):
    """コマンドの標準出力だけを取得し、失敗を握りつぶさない。"""
    return run(args, stdout=subprocess.PIPE, text=True).stdout.strip()


def absolute(value):
    """設定のパスを正規化せずに検査し、暗黙の別パスへの置換を防ぐ。"""
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts or value.startswith("//") or "\x00" in value:
        raise ValueError("設定には正規化済みの絶対パスが必要です")
    return path


def private_json(path):
    """実行ユーザー所有の0600通常ファイルだけを設定として読み込む。"""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError("設定は実行ユーザー所有の0600通常ファイルにしてください")
    if info.st_size > 32768:
        raise ValueError("設定ファイルが大きすぎます")
    return json.loads(path.read_text())


def digest(path):
    """大きなバックアップも一括読込みせずSHA-256を計算する。"""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save_json(path, value):
    """0600で同期してから同じディレクトリ内で置換する。"""
    fd, temporary = tempfile.mkstemp(prefix=".update-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def verify_archive(path):
    """停止後のデータアーカイブを最後まで読み、破損と空のバックアップを拒否する。"""
    files = 0
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            if member.isfile():
                files += 1
                with archive.extractfile(member) as stream:
                    while stream.read(1024 * 1024):
                        pass
    if not files:
        raise ValueError("バックアップにファイルがありません")
    with gzip.open(path, "rb") as stream:
        while stream.read(1024 * 1024):
            pass
    checksum = digest(path)
    checksum_file = path.with_suffix(path.suffix + ".sha256")
    with checksum_file.open("x") as stream:
        os.chmod(checksum_file, 0o600)
        stream.write(checksum + "  " + path.name + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def sync_directory(path):
    """ファイル名の作成・置換もディレクトリに同期する。"""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_config(path):
    """Docker/systemdそれぞれの必須項目と、設定にない項目を検査する。"""
    config = private_json(path)
    mode = config.get("mode")
    required = {
        "docker": {"mode", "project_directory", "compose_files", "service", "data_destination", "override_file"},
        "systemd": {"mode", "unit", "binary", "config", "data_dir", "go_binary"},
    }
    if mode not in required or set(config) != required[mode]:
        raise ValueError("更新対象の設定項目を確認してください")
    if mode == "docker":
        for name in ("project_directory", "data_destination", "override_file"):
            absolute(config[name])
        if not isinstance(config["compose_files"], list) or not config["compose_files"]:
            raise ValueError("Composeファイルを指定してください")
        for file in config["compose_files"]:
            absolute(file)
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", config["service"]):
            raise ValueError("更新サービス名が不正です")
    else:
        for name in ("binary", "config", "data_dir", "go_binary"):
            absolute(config[name])
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}\.service", config["unit"]):
            raise ValueError("systemdのサービス名が不正です")
    return config


class Docker:
    """BBSだけを交換し、公開入口・証明書サービス・既存のCompose設定を維持する。"""

    def __init__(self, config, source, revision, job):
        self.c, self.source, self.revision, self.job = config, source, revision, job
        self.tag = "oimobbs-update:" + revision[:12] + "-" + job.name

    def compose(self, *args, override=None):
        command = ["docker", "compose", "--project-directory", self.c["project_directory"]]
        for file in self.c["compose_files"]:
            command += ["-f", file]
        active = Path(self.c["override_file"])
        if active.exists():
            if active.is_symlink():
                raise ValueError("更新用Composeファイルにリンクは使えません")
            command += ["-f", str(active)]
        if override:
            command += ["-f", str(override)]
        return command + list(args)

    def container(self):
        ids = output(self.compose("ps", "--all", "--quiet", self.c["service"])).splitlines()
        if len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{12,64}", ids[0]):
            raise ValueError("更新対象コンテナを一意に特定できません")
        return json.loads(output(["docker", "inspect", ids[0]]))[0]

    def deployment_digest(self):
        files = self.c["compose_files"] + [self.c["override_file"]]
        return {file: digest(Path(file)) if Path(file).exists() else "" for file in files}

    def app_config_digest(self, container):
        """稼働中の起動JSONを確認し、保存先全体がバックアップ対象のマウント内にあることを検査する。"""
        command = container["Config"].get("Cmd", [])
        if command.count("--config") != 1 or command.index("--config") + 1 >= len(command):
            raise ValueError("稼働中コンテナの起動設定を特定できません")
        config_path = PurePosixPath(command[command.index("--config") + 1])
        if not config_path.is_absolute():
            raise ValueError("コンテナの起動設定には絶対パスが必要です")
        raw = output(["docker", "exec", container["Id"], "/bin/cat", str(config_path)])
        actual = json.loads(raw).get("data_dir")
        if not isinstance(actual, str) or not actual:
            raise ValueError("稼働中の保存先を特定できません")
        data = PurePosixPath(posixpath.normpath(str(config_path.parent / actual)))
        destination = PurePosixPath(self.c["data_destination"])
        if not data.is_relative_to(destination):
            raise ValueError("バックアップ対象に掲示板の保存先が含まれていません")
        for mount in container["Mounts"]:
            path = PurePosixPath(mount["Destination"])
            if path != destination and path.is_relative_to(destination):
                raise ValueError("保存先の内側に別のマウントがあります。保存領域をまとめてから更新してください")
        return hashlib.sha256(raw.encode()).hexdigest()

    def prepare(self):
        """稼働構成を固定し、停止前に試験・vet・新イメージのビルドを済ませる。"""
        old = self.container()
        if not old["State"]["Running"]:
            raise ValueError("掲示板が稼働していません")
        deployment = self.deployment_digest()
        app_config = self.app_config_digest(old)
        run(["docker", "build", "--pull", "--target", "update-check", str(self.source)])
        run(["docker", "build", "--target", "runtime", "--label", "org.opencontainers.image.revision=" + self.revision, "--tag", self.tag, str(self.source)])
        image = output(["docker", "image", "inspect", "--format", "{{.Id}}", self.tag])
        override = self.job / "deployment.json"
        save_json(override, {"services": {self.c["service"]: {"image": self.tag}}})
        run(self.compose("config", "--quiet", override=override))
        if deployment != self.deployment_digest():
            raise ValueError("ビルド中にCompose設定が変わりました")
        save_json(self.job / "prepared.json", {"container": old, "image": image, "deployment": deployment, "app_config": app_config, "override": digest(override)})

    def backup(self, old):
        """元のユーザー・イメージで停止済みの保存先をアーカイブし、読戻し検証する。"""
        mounts = [m for m in old["Mounts"] if m["Destination"] == self.c["data_destination"]]
        if len(mounts) != 1 or mounts[0]["Type"] not in ("volume", "bind"):
            raise ValueError("データのマウント元を特定できません")
        mount = mounts[0]
        source = mount.get("Name") if mount["Type"] == "volume" else mount["Source"]
        if not source or any(char in source for char in ",\n\r\x00"):
            raise ValueError("データマウントの設定が不正です")
        args = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
        if old["Config"].get("User"):
            args += ["--user", old["Config"]["User"]]
        args += ["--mount", "type=" + mount["Type"] + ",source=" + source + ",target=/data,readonly", "--entrypoint", "/bin/tar", old["Image"], "-czf", "-", "-C", "/data", "."]
        path = self.job / "data.tar.gz"
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            run(args, stdout=stream)
            stream.flush()
            os.fsync(stream.fileno())
        verify_archive(path)

    def apply(self):
        """稼働構成を再照合し、停止・バックアップが成功した場合だけBBSを置き換える。"""
        prepared = private_json(self.job / "prepared.json")
        old, current = prepared["container"], self.container()
        if (old["Id"], old["Image"]) != (current["Id"], current["Image"]) or prepared["deployment"] != self.deployment_digest():
            raise ValueError("検証後に稼働コンテナまたはCompose設定が変わりました")
        if prepared["app_config"] != self.app_config_digest(current):
            raise ValueError("検証後に掲示板の起動設定が変わりました")
        if output(["docker", "image", "inspect", "--format", "{{.Id}}", self.tag]) != prepared["image"]:
            raise ValueError("検証したイメージが変わりました")
        override = self.job / "deployment.json"
        if digest(override) != prepared["override"]:
            raise ValueError("検証した更新先の設定が変わりました")
        run(["docker", "image", "tag", old["Image"], "oimobbs-update:before-" + self.job.name])
        # 正常停止とバックアップが完了するまでは新イメージへ置き換えない。
        try:
            run(self.compose("stop", "--timeout", "45", self.c["service"]))
            stopped = json.loads(output(["docker", "inspect", old["Id"]]))[0]
            if stopped["State"]["Running"]:
                raise ValueError("掲示板を停止できませんでした")
            self.backup(old)
        except Exception:
            run(["docker", "start", old["Id"]])
            raise
        # 停止前のイメージ・inspect・データを保存済み。起動失敗後は保存形式を戻さず手動で調査する。
        run(self.compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "120", self.c["service"], override=override))
        result = self.container()
        if result["Image"] != prepared["image"] or result["State"].get("Health", {}).get("Status") != "healthy":
            raise ValueError("更新後のイメージまたはヘルスチェックが一致しません")
        save_json(Path(self.c["override_file"]), {"services": {self.c["service"]: {"image": self.tag}}})


class Systemd:
    """停止前にビルドし、データと旧バイナリを保存してから原子的に置き換える。"""

    def __init__(self, config, source, revision, job):
        self.c, self.source, self.revision, self.job = config, source, revision, job

    def fingerprint(self):
        binary, config = Path(self.c["binary"]), Path(self.c["config"])
        if binary.is_symlink() or config.is_symlink() or not binary.is_file() or not config.is_file():
            raise ValueError("バイナリと起動設定には通常ファイルが必要です")
        actual = json.loads(config.read_text()).get("data_dir")
        if not isinstance(actual, str) or not actual or (config.parent / actual).resolve() != Path(self.c["data_dir"]).resolve():
            raise ValueError("バックアップ対象と掲示板の保存先が一致しません")
        return {"binary": digest(binary), "config": digest(config)}

    def prepare(self):
        """現在のバイナリ・起動設定を固定し、稼働を続けたまま試験とビルドを行う。"""
        run(["systemctl", "is-active", "--quiet", self.c["unit"]])
        before = self.fingerprint()
        env = {**os.environ, "CGO_ENABLED": "0", "GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local"}
        go = self.c["go_binary"]
        run([go, "test", "-timeout=5m", "./internal/adminauth", "./internal/webui", "./internal/publicedge", "./internal/selfupdate"], cwd=self.source, env=env)
        run([go, "vet", "./cmd/...", "./internal/..."], cwd=self.source, env=env)
        run([go, "build", "-trimpath", "-ldflags=-s -w", "-o", str(self.job / "oimobbs.new"), "./cmd/oimobbs"], cwd=self.source, env=env)
        save_json(self.job / "prepared.json", {"deployment": before, "candidate": digest(self.job / "oimobbs.new")})

    def backup(self):
        """停止済みデータ・旧バイナリ・起動JSONを保存し、アーカイブを読戻し検証する。"""
        data = Path(self.c["data_dir"])
        if data.is_symlink() or not data.is_dir() or self.job.is_relative_to(data):
            raise ValueError("データとバックアップには別の通常ディレクトリが必要です")
        path = self.job / "data.tar.gz"
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            with tarfile.open(fileobj=stream, mode="w:gz", dereference=False) as archive:
                archive.add(data, arcname=".")
            stream.flush()
            os.fsync(stream.fileno())
        verify_archive(path)
        shutil.copy2(self.c["binary"], self.job / "oimobbs.before")
        shutil.copy2(self.c["config"], self.job / "config.before.json")
        os.chmod(self.job / "config.before.json", 0o600)
        for name in ("oimobbs.before", "config.before.json"):
            with (self.job / name).open("rb") as stream:
                os.fsync(stream.fileno())
        sync_directory(self.job)

    def install(self):
        """所有者と実行権限を維持し、同じディレクトリで新バイナリへ原子的に置き換える。"""
        binary = Path(self.c["binary"])
        old = binary.stat()
        fd, temporary = tempfile.mkstemp(prefix=".oimobbs-update-", dir=binary.parent)
        try:
            with os.fdopen(fd, "wb") as stream, (self.job / "oimobbs.new").open("rb") as source:
                shutil.copyfileobj(source, stream)
                os.fchmod(stream.fileno(), stat.S_IMODE(old.st_mode))
                os.fchown(stream.fileno(), old.st_uid, old.st_gid)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, binary)
            descriptor = os.open(binary.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def apply(self):
        """停止前に外部変更を照合し、バックアップ・置換・再起動・ヘルスチェックを行う。"""
        prepared = private_json(self.job / "prepared.json")
        if prepared["deployment"] != self.fingerprint() or prepared["candidate"] != digest(self.job / "oimobbs.new"):
            raise ValueError("検証後にバイナリまたは起動設定が変わりました")
        try:
            run(["systemctl", "stop", self.c["unit"]])
            if output(["systemctl", "show", "--property=ActiveState", "--value", self.c["unit"]]) != "inactive":
                raise ValueError("掲示板を停止できませんでした")
            self.backup()
        except Exception:
            run(["systemctl", "start", self.c["unit"]])
            raise
        try:
            self.install()
        except Exception:
            if self.binary_unchanged(prepared):
                run(["systemctl", "start", self.c["unit"]])
            raise
        run(["systemctl", "start", self.c["unit"]])
        # 起動直後の一時的な応答待ちだけを、上限付きで確認する。
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            probe = subprocess.run([self.c["binary"], "healthcheck", "--config", self.c["config"]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if probe.returncode == 0:
                run(["systemctl", "is-active", "--quiet", self.c["unit"]])
                return
            time.sleep(1)
        raise ValueError("再起動後のヘルスチェックに失敗しました")

    def binary_unchanged(self, prepared):
        """置換前の失敗に限って元のサービスを再開し、更新後データで旧版を起動しない。"""
        binary = Path(self.c["binary"])
        return binary.is_file() and digest(binary) == prepared["deployment"]["binary"]


def main():
    """更新器が用意したジョブ内だけでprepare/applyを実行する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "apply"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--job", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config_path, source, job = absolute(args.config), absolute(args.source), absolute(args.job)
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision) or source != job / "source" or not re.fullmatch(r"[a-f0-9]{24}", job.name):
        raise ValueError("更新ジョブの入力が不正です")
    config = load_config(config_path)
    config_hash = digest(config_path)
    saved = job / "host-config-sha256.json"
    if args.action == "prepare":
        save_json(saved, {"sha256": config_hash})
    elif private_json(saved) != {"sha256": config_hash}:
        raise ValueError("検証後に更新設定が変更されました")
    backend = (Docker if config["mode"] == "docker" else Systemd)(config, source, args.revision, job)
    getattr(backend, args.action)()


if __name__ == "__main__":
    main()
