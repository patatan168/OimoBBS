#!/usr/bin/env python3
"""隔離HTTP/3サーバーを独立実装で照合し、304のQPACK・UDP量を比較する。

実行にはテスト専用環境のaioquicが必要。証明書検証の省略はloopback/隔離origin専用。
"""
import argparse
import asyncio
import hashlib
import json
import ssl
import statistics
import time
from urllib.parse import urlparse

from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset
from aioquic.tls import CipherSuite


class MeasuredH3(H3Connection):
    """エンコード済みHEADERS長を計数し、blocked解除の再処理は二重計数しない。"""
    def __init__(self, quic):
        super().__init__(quic)
        self.header_tx = 0
        self.header_rx = 0

    def _encode_headers(self, stream_id, headers):
        block = super()._encode_headers(stream_id, headers)
        self.header_tx += len(block)
        return block

    def _decode_headers(self, stream_id, frame_data):
        if frame_data is not None:
            self.header_rx += len(frame_data)
        return super()._decode_headers(stream_id, frame_data)


class Client(QuicConnectionProtocol):
    """HTTP/3の実応答とUDP payloadの送受信量を同一接続で記録する。"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = MeasuredH3(self._quic)
        self.pending = {}
        self.tx = self.rx = 0
        original = self._quic.datagrams_to_send

        def measured(now):
            packets = original(now=now)
            self.tx += sum(len(data) for data, _ in packets)
            return packets
        self._quic.datagrams_to_send = measured

    def datagram_received(self, data, addr):
        self.rx += len(data)
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for future, _, _ in self.pending.values():
                if not future.done():
                    future.set_exception(RuntimeError(repr(event)))
        if isinstance(event, StreamReset) and event.stream_id in self.pending:
            future = self.pending[event.stream_id][0]
            if not future.done():
                future.set_exception(RuntimeError(repr(event)))
        for h3event in self.h3.handle_event(event):
            if isinstance(h3event, (HeadersReceived, DataReceived)):
                state = self.pending.get(h3event.stream_id)
                if state is None:
                    continue
                future, headers, data = state
                if isinstance(h3event, HeadersReceived):
                    headers.extend(h3event.headers)
                else:
                    data.extend(h3event.data)
                if h3event.stream_ended and not future.done():
                    future.set_result((headers, bytes(data)))

    async def request(self, authority, path, condition=None, body=None):
        stream = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self.pending[stream] = (future, [], bytearray())
        headers = [(b':method', b'POST' if body is not None else b'GET'),
                   (b':scheme', b'https'), (b':authority', authority.encode()),
                   (b':path', path.encode()), (b'accept-encoding', b'gzip'),
                   (b'user-agent', b'oimo-independent-http3-probe')]
        if condition:
            headers.append((b'if-none-match', condition))
        if body is not None:
            headers.append((b'content-length', str(len(body)).encode()))
        self.h3.send_headers(stream, headers, end_stream=body is None)
        if body is not None:
            self.h3.send_data(stream, body, end_stream=True)
        self.transmit()
        try:
            return await asyncio.wait_for(future, timeout=10)
        finally:
            del self.pending[stream]

    def counters(self):
        return dict(tx=self.tx, rx=self.rx, headers_tx=self.h3.header_tx,
                    headers_rx=self.h3.header_rx,
                    encoder_tx=self.h3._encoder_bytes_sent,
                    encoder_rx=self.h3._encoder_bytes_received,
                    decoder_tx=self.h3._decoder_bytes_sent,
                    decoder_rx=self.h3._decoder_bytes_received)


async def run(args):
    origin = urlparse(args.origin)
    config = QuicConfiguration(is_client=True, alpn_protocols=['h3'])
    config.verify_mode = ssl.CERT_NONE
    if args.cipher != "default":
        config.cipher_suites = [getattr(CipherSuite, args.cipher)]
    async with connect(origin.hostname, origin.port or 443, configuration=config,
                       create_protocol=Client) as client:
        headers, full = await client.request(origin.netloc, '/thread.dat')
        assert dict(headers)[b':status'] == b'200' and len(full) > 0
        etag = dict(headers)[b'etag']
        # qpack双方の動的tableとACKを十分にwarmにする。
        for _ in range(64):
            headers, data = await client.request(origin.netloc, '/thread.dat', etag)
            assert dict(headers)[b':status'] == b'304' and not data
        await asyncio.sleep(0.05)
        if args.key_update:
            client._quic.request_key_update()
        before = client.counters()
        cpu = time.process_time()
        start = time.perf_counter()
        durations = []
        success = errors = 0
        first_error = None
        for _ in range(args.requests):
            t = time.perf_counter()
            try:
                headers, data = await client.request(origin.netloc, '/thread.dat', etag)
                assert dict(headers)[b':status'] == b'304' and not data
                success += 1
            except Exception as exc:
                errors += 1
                first_error = first_error or repr(exc)
            durations.append((time.perf_counter()-t)*1000)
        elapsed = time.perf_counter()-start
        cpu = time.process_time()-cpu
        await asyncio.sleep(0.05)
        after = client.counters()
        result = dict(issued=args.requests, success=success, errors=errors,
                      negotiated_cipher=client._quic.tls.key_schedule.cipher_suite.name,
                      first_error=first_error, seconds=elapsed,
                      requests_per_second=args.requests/elapsed,
                      client_cpu_ms=cpu*1000, p50_ms=statistics.median(durations),
                      p95_ms=sorted(durations)[int(len(durations)*.95)],
                      full_body_sha256=hashlib.sha256(full).hexdigest(),
                      counters={key: after[key]-before[key] for key in before},
                      per_request={key: (after[key]-before[key])/args.requests for key in before})
        print(json.dumps(result, indent=2))
        if errors:
            raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', default='https://127.0.0.1:8443')
    parser.add_argument('--requests', type=int, default=1000)
    parser.add_argument('--key-update', action='store_true')
    parser.add_argument('--cipher', choices=['default', 'AES_128_GCM_SHA256', 'AES_256_GCM_SHA384', 'CHACHA20_POLY1305_SHA256'], default='default')
    args = parser.parse_args()
    if args.requests < 1:
        parser.error('--requests must be positive')
    asyncio.run(run(args))
