#!/usr/bin/env python3
"""更新済み証明書と鍵を一つのPEMにまとめ、検証サーバーへ原子的に公開する。"""
import os
from pathlib import Path

lineage = Path(os.environ["RENEWED_LINEAGE"])
bundle = (lineage / "fullchain.pem").read_bytes() + (lineage / "privkey.pem").read_bytes()
path = Path("/tls/server.pem.new")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as stream:
    os.fchmod(stream.fileno(), 0o600)
    os.fchown(stream.fileno(), 10001, 10001)
    stream.write(bundle)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(path, "/tls/server.pem")
fd = os.open("/tls", os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
