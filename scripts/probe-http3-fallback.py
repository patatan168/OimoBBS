#!/usr/bin/env python3
"""ルーターを変更せず、実Chromiumに対するUDP黙殺とTCP継続を隔離relayで検証する。"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def run(args):
    """Docker操作は専用ネットワークと短命コンテナだけを対象にする。"""
    return subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=True)


class Relay(asyncio.DatagramProtocol):
    """接続単位でUDPの送信元を固定し、遮断時はICMPを返さず両方向を捨てる。"""
    def __init__(self, upstream):
        self.upstream = upstream
        self.transport = None
        self.clients = {}
        self.tasks = set()
        self.dropping = False
        self.stats = {'forwarded_udp': 0, 'dropped_udp': 0, 'tcp_connections': 0}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if self.dropping:
            self.stats['dropped_udp'] += 1
            return
        entry = self.clients.get(address)
        if entry is not None:
            if isinstance(entry, list):
                if len(entry) < 16:
                    entry.append(data)
            else:
                entry.sendto(data)
                self.stats['forwarded_udp'] += 1
            return
        if len(self.clients) >= 16:
            return
        self.clients[address] = [data]
        task = asyncio.create_task(self.connect(address))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def connect(self, address):
        """暗号化済みのdatagramだけを中継し、内容や鍵へ介入しない。"""
        relay = self

        class Reply(asyncio.DatagramProtocol):
            def datagram_received(self, data, _):
                if relay.dropping:
                    relay.stats['dropped_udp'] += 1
                else:
                    relay.transport.sendto(data, address)
                    relay.stats['forwarded_udp'] += 1

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Reply, remote_addr=self.upstream)
        queued = self.clients[address]
        self.clients[address] = transport
        for data in queued:
            if self.dropping:
                self.stats['dropped_udp'] += 1
            else:
                transport.sendto(data)
                self.stats['forwarded_udp'] += 1

    def close(self):
        for task in self.tasks:
            task.cancel()
        for client in self.clients.values():
            if not isinstance(client, list):
                client.close()
        if self.transport:
            self.transport.close()


async def probe(args, binary, output, network, name):
    """TCP/UDP同一portをloopbackにだけ公開し、試験終了時は全relayを閉じる。"""
    upstream = [None]
    tcp_tasks = set()
    relay = Relay(None)

    async def tcp(reader, writer):
        relay.stats['tcp_connections'] += 1
        task = asyncio.current_task()
        tcp_tasks.add(task)
        peer = None
        try:
            remote, peer = await asyncio.open_connection(*upstream[0])

            async def copy(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()

            jobs = [asyncio.create_task(copy(reader, peer)), asyncio.create_task(copy(remote, writer))]
            try:
                await asyncio.wait(jobs, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for job in jobs:
                    job.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            if peer:
                peer.close()
            tcp_tasks.discard(task)

    async def control(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
            line = request.split(b'\r\n', 1)[0]
            if line == b'POST /drop HTTP/1.1':
                relay.dropping = True
            elif line != b'GET /stats HTTP/1.1':
                return
            body = json.dumps(relay.stats).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(tcp, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    control_server = await asyncio.start_server(control, '127.0.0.1', 0)
    control_port = control_server.sockets[0].getsockname()[1]
    await asyncio.get_running_loop().create_datagram_endpoint(lambda: relay, local_addr=('127.0.0.1', port))
    try:
        origin = f'https://localhost:{port}'
        run(['docker', 'run', '-d', '--name', name, '--network', network, '--cpus', '2', '--memory', '512m', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '-v', f'{binary}:/probe:ro', 'alpine:3.23', '/probe', '-serve', '-certificate', 'ecdsa', '-identity-only', '-origin', origin])
        for _ in range(100):
            state = json.loads(run(['docker', 'inspect', name]).stdout)[0]
            if not state['State']['Running']:
                raise RuntimeError(run(['docker', 'logs', name]).stderr)
            if 'ready' in run(['docker', 'logs', name]).stdout:
                break
            await asyncio.sleep(.05)
        else:
            raise RuntimeError('server readiness timeout')
        upstream[0] = (state['NetworkSettings']['Networks'][network]['IPAddress'], 8443)
        relay.upstream = upstream[0]
        # veth作成通知がChromiumの既存socketを切らないよう、起動前にネットワークを安定させる。
        await asyncio.sleep(3)
        process = await asyncio.create_subprocess_exec(args.node, 'scripts/probe-http3-fallback.mjs', '--origin', origin, '--control', f'http://127.0.0.1:{control_port}', '--chrome', args.chrome, '--profile', str(output/'profile'), cwd=ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 180)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        (output/'results.json').write_bytes(stdout)
        (output/'browser.stderr').write_bytes(stderr)
        (output/'relay.json').write_text(json.dumps(relay.stats, indent=2)+'\n')
        if process.returncode:
            raise RuntimeError(stderr.decode()[-8000:])
        print(stdout.decode())
    finally:
        server.close()
        control_server.close()
        relay.close()
        for task in list(tcp_tasks):
            task.cancel()
        await asyncio.gather(*tcp_tasks, return_exceptions=True)
        logs = subprocess.run(['docker', 'logs', name], cwd=ROOT, text=True, capture_output=True)
        (output/'server.log').write_text(logs.stdout+logs.stderr)
        subprocess.run(['docker', 'rm', '-f', name], cwd=ROOT, capture_output=True)


def main():
    """証明書例外もprofileも使い捨てにし、製品設定やhostの信頼storeを変更しない。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='var/native-quic-20261103/fallback')
    parser.add_argument('--chrome', required=True)
    parser.add_argument('--node', default='node')
    args = parser.parse_args()
    output = (ROOT/args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = output/'bench'
    run(['python3', 'scripts/quic-reference.py', 'build-benchmark', '--output', str(binary)])
    network = f'oimo-h3-fallback-{os.getpid()}'
    run(['docker', 'network', 'create', '--internal', network])
    try:
        asyncio.run(probe(args, binary, output, network, network+'-server'))
    finally:
        run(['docker', 'network', 'rm', network])


if __name__ == '__main__':
    main()
