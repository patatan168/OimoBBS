"""隔離DATをネイティブ実装で比較する。製品Go実装の速度とは区別する。"""
import ctypes as c
import ctypes.util
import gzip
import json
import pathlib
import statistics
import sys
import time
b = c.CDLL(ctypes.util.find_library('brotlienc'))
b.BrotliEncoderMaxCompressedSize.argtypes = [c.c_size_t]
b.BrotliEncoderMaxCompressedSize.restype = c.c_size_t
b.BrotliEncoderCompress.argtypes = [c.c_int,c.c_int,c.c_int,c.c_size_t,c.c_void_p,c.POINTER(c.c_size_t),c.c_void_p]
d = c.CDLL(ctypes.util.find_library('brotlidec'))
d.BrotliDecoderDecompress.argtypes = [c.c_size_t,c.c_void_p,c.POINTER(c.c_size_t),c.c_void_p]
z = c.CDLL(ctypes.util.find_library('zstd'))
z.ZSTD_compressBound.argtypes = [c.c_size_t]
z.ZSTD_compressBound.restype = c.c_size_t
z.ZSTD_compress.argtypes = [c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t,c.c_int]
z.ZSTD_compress.restype = c.c_size_t
z.ZSTD_decompress.argtypes = [c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t]
z.ZSTD_decompress.restype = c.c_size_t
z.ZSTD_isError.argtypes = [c.c_size_t]
def encode(codec,level,raw):
    if codec == 'gzip':
        return gzip.compress(raw,compresslevel=level,mtime=0)
    capacity = b.BrotliEncoderMaxCompressedSize(len(raw)) if codec == 'br' else z.ZSTD_compressBound(len(raw))
    out = c.create_string_buffer(capacity)
    if codec == 'br':
        size = c.c_size_t(capacity)
        if not b.BrotliEncoderCompress(level,22,0,len(raw),raw,c.byref(size),out):
            raise RuntimeError('brotli encoding failed')
        return out.raw[:size.value]
    size = z.ZSTD_compress(out,capacity,raw,len(raw),level)
    if z.ZSTD_isError(size):
        raise RuntimeError('zstd encoding failed')
    return out.raw[:size]
def decode(codec,encoded,size):
    if codec == 'gzip':
        return gzip.decompress(encoded)
    out = c.create_string_buffer(size)
    if codec == 'br':
        decoded = c.c_size_t(size)
        if d.BrotliDecoderDecompress(len(encoded),encoded,c.byref(decoded),out) != 1:
            raise RuntimeError('brotli decoding failed')
        return out.raw[:decoded.value]
    decoded = z.ZSTD_decompress(out,size,encoded,len(encoded))
    if z.ZSTD_isError(decoded):
        raise RuntimeError('zstd decoding failed')
    return out.raw[:decoded]
rows=[]
for path in sys.argv[1:]:
    raw=pathlib.Path(path).read_bytes()
    for codec,levels in [('gzip',[1,6,9]),('br',[4,6,9,11]),('zstd',[1,3,6,9,12,19])]:
        for level in levels:
            times=[]
            for _ in range(5 if level in (11,19) else 20):
                start=time.perf_counter()
                encoded=encode(codec,level,raw)
                times.append((time.perf_counter()-start)*1000)
            start=time.perf_counter()
            assert decode(codec,encoded,len(raw))==raw
            rows.append({'fixture':path,'implementation':'native-library','codec':codec,'level':level,'raw_bytes':len(raw),'bytes':len(encoded),'median_compress_ms':statistics.median(times),'decompress_ms':(time.perf_counter()-start)*1000})
print(json.dumps(rows,indent=2))
