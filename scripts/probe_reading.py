"""隔離サーバーの確定DAT・Web・一覧について、全文と再検証を分けて測る。"""
from codec_probe_decode import decode


def reading_phases(probe, key, dat, requests, kinds=("dat", "html", "subject"), cases=None):
    """各表現を事前取得し、本文・Range・ETag条件を照合する。再試行はしない。"""
    phases = []
    known = {f"{kind}_{coding}_{mode}" for kind in ("dat", "html", "subject")
             for coding in ("identity", "gzip", "zstd") for mode in ("full", "304")}
    known.update(("dat_delta_last_post", "dat_delta_unchanged"))
    if cases and (not set(cases) <= known or any(name.split("_", 1)[0] not in kinds for name in cases)):
        raise ValueError("invalid reading case selection")

    def load(name, *args):
        if not cases or name in cases:
            phases.append(probe.load(name, *args, requests=requests))
    paths = [("dat", f"/probe/dat/{key}.dat", dat),
             ("html", f"/test/read.cgi/probe/{key}/", None),
             ("subject", "/probe/subject.txt", None)]
    for kind, path, expected in paths:
        if kind not in kinds:
            continue
        for coding in ("identity", "gzip", "zstd"):
            headers = {"Accept-Encoding": coding}
            status, received, body, _ = probe.request("GET", path, headers=headers)
            decoded = decode(received.get("content-encoding"), body)
            if status != 200 or expected is not None and decoded != expected:
                raise RuntimeError(f"{kind} {coding} fixture mismatch")
            if expected is None:
                expected = decoded
            load(f"{kind}_{coding}_full", path, headers, 200, expected)
            conditional = {**headers, "If-None-Match": received["etag"]}
            load(f"{kind}_{coding}_304", path, conditional, 304, b"")
        if kind == "dat":
            # 最終行（1000レス終了時のsystemレス）と、更新のない末尾1byteを分離する。
            for name, offset in (("last_post", dat.rfind(b"\n", 0, len(dat)-1)+1), ("unchanged", len(dat)-1)):
                headers = {"Accept-Encoding": "identity", "Range": f"bytes={offset}-"}
                load(f"dat_delta_{name}", path, headers, 206, dat[offset:])
    return phases
