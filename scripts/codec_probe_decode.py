"""検証ホスト専用の有界decoder。圧縮ライブラリは製品コンテナに追加しない。"""
import ctypes as c
import ctypes.util
import gzip
import threading

zstd_path = ctypes.util.find_library('zstd')
if not zstd_path:
    raise RuntimeError('verification host requires libzstd')
zstd = c.CDLL(zstd_path)
zstd.ZSTD_decompress.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t]
zstd.ZSTD_decompress.restype = c.c_size_t
workspace = threading.local()

def decode(coding, body):
    """展開上限8MiBで検証し、要求ごとの大容量buffer確保・全容量copyを避ける。"""
    if coding == 'gzip':
        return gzip.decompress(body)
    if not hasattr(workspace, 'buffer'):
        workspace.buffer = c.create_string_buffer(8 << 20)
    out = workspace.buffer
    if coding == 'zstd':
        size = zstd.ZSTD_decompress(out, len(out), body, len(body))
        if size > len(out):
            raise RuntimeError('zstd decode failed or exceeds limit')
        return c.string_at(out, size)
    if coding:
        raise RuntimeError('unexpected content encoding')
    return body
