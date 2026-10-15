"""製品の圧縮cache/HTTP判断/80Mbps送信器を隔離TLSで比較する。稼働投稿・遠隔NICは含まない。"""
import argparse,concurrent.futures,ctypes as c,ctypes.util,gzip,hashlib,http.client,json,os,pathlib,socket,ssl,subprocess,tempfile,threading,time
import importlib.util
spec=importlib.util.spec_from_file_location('resourceprobe',pathlib.Path(__file__).with_name('probe-thread-resources.py'))
resource=importlib.util.module_from_spec(spec);spec.loader.exec_module(resource)
z=c.CDLL(ctypes.util.find_library('zstd'))
z.ZSTD_decompress.argtypes=[c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t];z.ZSTD_decompress.restype=c.c_size_t

def decode(coding,body):
    """ホストのdecoderで受信byteを検証する。サーバーのCPUと区別する。"""
    if coding=='gzip':return gzip.decompress(body)
    out=c.create_string_buffer(1<<20)
    size=z.ZSTD_decompress(out,len(out),body,len(body))
    if size>len(out):raise RuntimeError('zstd decode failed')
    return c.string_at(out,size)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',default='oimobbs-validation:local')
    parser.add_argument('--binary',default='var/codecprobe')
    parser.add_argument('--output',default='var/codec-http-constrained.json')
    parser.add_argument('--seconds',type=int,default=5)
    args=parser.parse_args();rows=[]
    with tempfile.TemporaryDirectory(prefix='oimo-codec-tls-') as tmp:
        root=pathlib.Path(tmp);cert=root/'cert.pem';key=root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        key.chmod(0o600)
        for cpu,memory in [('1','256m'),('2','1g')]:
            for corpus in ['entropy','text']:
                for updates in [0,20]:
                    name=f'oimo-codec-http-{cpu}-{corpus}-{updates}'
                    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                    probe=None
                    try:
                        subprocess.run(['docker','run','-d','--name',name,'--network','host','--user',f'{os.getuid()}:{os.getgid()}','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--cpus',cpu,'--memory',memory,'--memory-swap',memory,'-v',str(pathlib.Path(args.binary).resolve())+':/codecprobe:ro','-v',tmp+':/tls:ro','--entrypoint','/codecprobe',args.image,'-listen',f'127.0.0.1:{port}','-cert','/tls/cert.pem','-key','/tls/key.pem','-corpus',corpus,'-updates',str(updates)],stdout=subprocess.DEVNULL,check=True)
                        pid=subprocess.check_output(['docker','inspect','--format','{{.State.Pid}}',name],text=True).strip()
                        if pid=='0':raise RuntimeError(subprocess.check_output(['docker','logs',name],text=True))
                        group=pathlib.Path('/sys/fs/cgroup')/pathlib.Path(f'/proc/{pid}/cgroup').read_text().split('::',1)[1].strip().lstrip('/')
                        probe=resource.Probe(port,cert,group)
                        for attempt in range(100):
                            try:
                                if probe.request('GET','/status')[0]==200:break
                            except (OSError,http.client.HTTPException):probe.local=threading.local()
                            time.sleep(.05)
                        else:raise RuntimeError('server startup failed')
                        for coding in ['gzip','zstd']:
                            probe.phase=coding;before=resource.counters(group)
                            status_start=json.loads(probe.request('GET','/status')[2]);start=time.monotonic();client_cpu=time.process_time()
                            def worker(index):
                                out=[]
                                while time.monotonic()-start<args.seconds:
                                    status,h,body,elapsed=probe.request('GET','/',headers={'Accept-Encoding':coding+',identity;q=0'})
                                    decoded=decode(coding,body) if status==200 else b''
                                    ok=status==200 and h.get('content-encoding')==coding and hashlib.sha256(decoded).hexdigest()==h.get('x-body-sha256')
                                    out.append((elapsed,len(body),ok))
                                return out
                            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:outcomes=sum(pool.map(worker,range(16)),[])
                            duration=time.monotonic()-start;after=resource.counters(group)
                            status_end=json.loads(probe.request('GET','/status')[2]);latencies=sorted(row[0] for row in outcomes)
                            row={'cpu_limit':cpu,'memory_limit':memory,'corpus':corpus,'updates_per_second':updates,'coding':coding,'requests':len(outcomes),'seconds':duration,'rps':len(outcomes)/duration,'p95_ms':latencies[int(len(latencies)*.95)],'body_bytes':sum(row[1] for row in outcomes),'errors':sum(not row[2] for row in outcomes),'cpu_cores':(after['cpu_usec']-before['cpu_usec'])/1e6/duration,'client_cpu_seconds':time.process_time()-client_cpu,'scope':'closed-loop peak with host decoding; body throughput must approach budget for bandwidth comparison','cache_builds':status_end['builds']-status_start['builds'],'cache_hits':status_end['hits']-status_start['hits'],'cache_used_bytes':status_end['used_bytes'],'memory_peak_bytes':int((group/'memory.peak').read_text()),'oom_kill_delta':after['oom_kill']-before['oom_kill'],'throttled_usec_delta':after['throttled_usec']-before['throttled_usec']}
                            rows.append(row);p=pathlib.Path(args.output);p.write_text(json.dumps({'scope':__doc__,'rows':rows},indent=2));p.chmod(0o600)
                            print(cpu,memory,corpus,updates,coding,round(row['rps'],2),round(row['p95_ms'],2),round(row['cpu_cores'],2),row['memory_peak_bytes'],row['errors'],flush=True)
                            if row['errors'] or row['oom_kill_delta']:raise RuntimeError('invalid HTTP/resource result')
                    finally:
                        if probe:probe.stop.set();probe.monitor.join()
                        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if __name__=='__main__':main()
