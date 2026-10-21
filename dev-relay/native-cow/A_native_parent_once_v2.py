"""One new Runtime sandbox/capture using existing verified offline PyPika input.
UB stays disabled. No downloads, existing-service changes, global device cleanup or automatic retries.
"""
import argparse,hashlib,http.client,json,os,re,socket,stat,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from urllib.parse import urlsplit,urlencode
ROOT=Path('/home/jwk/agent')
BASE=ROOT/'deployments/agentenv-native-fe63038'
UNIT='jwk-aenv-native-fe63038-node-a.service'
PORT=None
PENDING=ROOT/'relay/native-runtime-parent-node-a.pending.json'
OCI=ROOT/'relay/reports/node-a-cow-parent-mbw69dma/image'
IMAGE_SHA='sha256:039f1b18eb5c1bf56c074234e718af2f6156cbb729d638f05d1d8cf95dffe409'
MAX_IMAGE_BYTES=512*1024**2
ID=re.compile(r'[A-Za-z0-9_-]{1,128}')
NETWORK_KEYS=('HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy','ALL_PROXY','all_proxy','NO_PROXY','no_proxy','SSL_CERT_FILE','SSL_CERT_DIR')
def redact_child_output(text, env):
    for key in NETWORK_KEYS:
        value = env.get(key)
        if value and len(value) >= 8:
            text = text.replace(value, '[NETWORK_ENV_VALUE]')
    text = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', text)
    text = re.sub(r'(?i)(https?|socks5h?)://[^/\s@]+@', r'\1://[REDACTED]@', text)
    text = re.sub(r'https?://\S+\?\S+', '[URL query withheld]', text)
    return '\n'.join('[REDACTED authentication line]' if re.search(
        r'authorization|password|secret|bearer\s|access_token\s*[:=]', line, re.I)
        else line for line in text.splitlines())

class ChildFailure(RuntimeError):
    def __init__(self, log, code, stdout, stderr):
        super().__init__('Child command failed; diagnostics included: ' + log.name)
        self.diagnostics = {'stdout_file': log.name, 'stderr_file': log.stem + '.stderr.log',
                            'exit_code': code, 'stdout_tail': stdout, 'stderr_tail': stderr}

def need(ok, text):
    if not ok:
        raise RuntimeError(text)

def safe(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT) and path.resolve() == path, 'Outside or redirected path')
    if path.exists():
        need(path.lstat().st_uid == 1204, 'Unexpected file owner')
    return path

def read(path, limit=1024 * 1024):
    safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= limit, 'Unexpected file metadata')
        data = f.read(limit + 1)
        need(len(data) <= limit, 'Input grew beyond limit')
        return data

def save(path, obj):
    safe(path)
    data = (json.dumps(obj, indent=2) + '\n').encode()
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temp.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

def runtime_pid():
    r = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--property=ActiveState,MainPID,User,Group'],
                       capture_output=True, text=True, timeout=10, check=True)
    fields = dict(x.split('=', 1) for x in r.stdout.splitlines() if '=' in x)
    need(fields.get('ActiveState') == 'active' and fields.get('User') == fields.get('Group') == 'jwk', 'New native runtime not healthy/expected')
    pid = int(fields.get('MainPID', 0))
    need(pid > 1, 'Invalid runtime PID')
    ticks = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19]
    return pid, ticks

class Api:
    def __init__(self):
        self.key = read(BASE / 'config/api-key', 1024).decode().strip()
        need(re.fullmatch(r'e2b_[A-Za-z0-9._~-]+', self.key), 'Invalid API key format; value withheld')
        self.identity = runtime_pid()

    def call(self, method, path, data=None, timeout=20):
        need(runtime_pid() == self.identity, 'New native service changed; no request sent')
        allowed = path in ('/health', '/sandboxes-cold', '/v2/sandboxes?limit=1') or re.fullmatch(r'/sandboxes/[A-Za-z0-9_-]+(?:/snapshots)?', path)
        allowed = allowed or (method == 'GET' and re.fullmatch(
            r'/v2/sandboxes\?metadata=cow_parent_run%3D[0-9a-f]{32}&limit=2', path))
        need(allowed and method in ('GET', 'POST', 'DELETE'), 'API route outside experiment')
        conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=timeout)
        try:
            body = json.dumps(data).encode() if data is not None else None
            conn.request(method, path, body=body, headers={'X-API-Key': self.key, 'Content-Type': 'application/json'})
            response = conn.getresponse()
            raw = response.read(1024 * 1024 + 1)
            need(len(raw) <= 1024 * 1024, 'API reply exceeds limit')
            return response.status, json.loads(raw) if raw else None
        finally:
            conn.close()

def error_summary(body, key):
    if not isinstance(body, dict):
        return {'message': 'Non-object response body withheld'}
    message = body.get('message', '')
    if not isinstance(message, str):
        message = 'Non-text error message withheld'
    message = message.replace(key, '[REDACTED]')
    message = re.sub(r'e2b_[A-Za-z0-9._~-]+', '[REDACTED]', message)
    message = re.sub(r'https?://\S+\?\S+', '[URL query withheld]', message)
    return {'code': body.get('code') if isinstance(body.get('code'), int) else None,
            'message': message[:3000]}

def collect_fc_logs(sid, env, key):
    """Only this attempt's identified sandbox, bounded tails; never scan other Guests."""
    need(ID.fullmatch(sid) is not None, 'Invalid diagnostic sandbox identity')
    result = {'sandbox_id':sid, 'scope':'own_sandbox_log_tails', 'files':{}}
    for name in ('firecracker-stderr.log', 'firecracker-stdout.log', 'firecracker.log'):
        try:
            path = safe(BASE/'logs/firecracker'/sid/name)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as f:
                meta = os.fstat(f.fileno())
                need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1204, 'Unexpected log metadata')
                f.seek(max(0, meta.st_size-8192))
                tail = f.read(8192).decode(errors='replace').replace(key, '[REDACTED]')
            result['files'][name] = {'available':True, 'file_bytes':meta.st_size,
                                    'tail':redact_child_output(tail, env)}
        except Exception as e:
            result['files'][name] = {'available':False, 'error_type':type(e).__name__}
    return result

def parent_layer_inventory(snapshot_id):
    """Capture stored/allocated bytes, not Guest physical sharing or cache sizes."""
    result = {'phase': 'after_parent_capture_before_replay',
              'scope': 'stored_layer_metadata_only_no_shared_page_claim',
              'snapshot_id': snapshot_id, 'content_hashes_verified': False}
    try:
        repo = BASE / 'state/snapshot-store/repository'
        record = json.loads(read(repo / 'catalog/records' / (snapshot_id + '.json')))
        need(record.get('id') == snapshot_id and isinstance(record.get('committed'), dict), 'Committed snapshot record mismatch')
        committed = record['committed']
        for kind in ('memory', 'rootfs'):
            rows = []
            for item in committed.get(kind + '_layers', []):
                origin = 'Managed' if kind == 'memory' else next(iter(item), '')
                layer = item if kind == 'memory' else item.get(origin, {})
                digest = layer.get('digest', '')
                need(re.fullmatch(r'sha256:[0-9a-f]{64}', digest), 'Unexpected committed digest')
                row = {'origin': origin, 'digest': digest, 'stored_bytes_declared': layer.get('size')}
                if origin == 'Managed':
                    path = safe(repo / 'managed-layers' / (digest.replace(':', '_') + '.overlaybd.commit'))
                    try:
                        m = path.stat()
                        need(stat.S_ISREG(m.st_mode), 'Managed layer is not a regular file')
                        row.update(path=str(path), file_bytes=m.st_size, allocated_file_bytes=m.st_blocks * 512,
                                   dev=m.st_dev, inode=m.st_ino, mtime_ns=m.st_mtime_ns)
                    except Exception as e:
                        row['file_measurement'] = {'available': False, 'error_type': type(e).__name__}
                else:
                    row['file_measurement'] = {'available': False, 'reason': 'EXTERNAL_PLACEMENT_NOT_RESOLVED'}
                rows.append(row)
            result[kind] = rows
        result['available'] = True
    except Exception as e:
        result.update(available=False, error_type=type(e).__name__)
    return result

def verify_layout(layout, digest):
    def blob(d, size=None):
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', d), 'Unsupported blob digest')
        path = layout / 'blobs/sha256' / d.split(':')[1]
        safe(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            m = os.fstat(f.fileno())
            need(stat.S_ISREG(m.st_mode) and m.st_uid == 1204 and m.st_size <= MAX_IMAGE_BYTES, 'Invalid OCI blob')
            need(size is None or m.st_size == size, 'OCI blob length differs')
            h = hashlib.sha256()
            for part in iter(lambda: f.read(1024 * 1024), b''):
                h.update(part)
        need('sha256:' + h.hexdigest() == d, 'OCI blob hash differs')
        return path
    manifest = json.loads(read(blob(digest)))
    layers = manifest.get('layers', [])
    need(isinstance(layers, list) and 0 < len(layers) <= 32, 'Invalid layer count')
    total = sum(x['size'] for x in layers) + manifest['config']['size']
    need(0 < total <= MAX_IMAGE_BYTES, 'Image exceeds 512MiB compressed input budget')
    cfg = manifest['config']
    config = json.loads(read(blob(cfg['digest'], cfg['size'])))
    need(config.get('os') == 'linux' and config.get('architecture') == 'arm64', 'Image is not Linux ARM64')
    for layer in layers:
        blob(layer['digest'], layer['size'])
    return {'manifest_digest': digest, 'layer_count': len(layers), 'verified_compressed_bytes': total,
            'architecture': 'arm64', 'hashing_phase': 'preparation_before_memory_measurement'}

def checked_process(command, env, log, timeout):
    stderr_path = log.with_name(log.stem + '.stderr.log')
    code = None
    try:
        with log.open('wb') as output, stderr_path.open('wb') as error:
            r = subprocess.run([str(x) for x in command], stdin=subprocess.DEVNULL,
                               stdout=output, stderr=error, env=env, timeout=timeout)
        code = r.returncode
    except subprocess.TimeoutExpired:
        code = 'TIMEOUT'
    # stderr is diagnostic text, never manifest content. Bound and sanitize it
    # before returning or including it in the report; keep successful stdout
    # byte-for-byte intact for content-addressed manifest verification.
    def sanitized_log(path):
        with path.open('rb') as f:
            f.seek(0, os.SEEK_END)
            length = f.tell()
            f.seek(max(0, length - 65536))
            text = redact_child_output(f.read(65536).decode(errors='replace'), env)
        path.write_text(('[EARLIER DIAGNOSTICS TRUNCATED]\n' if length > 65536 else '') + text)
    sanitized_log(stderr_path)
    if code != 0:
        sanitized_log(log)
        def tail(path):
            with path.open('rb') as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 6000))
                return redact_child_output(f.read(6000).decode(errors='replace'), env)
        raise ChildFailure(log, code, tail(log), tail(stderr_path))


def cold_device_budget(config_bytes, tools_metadata):
    expected='5fce6e59350153e8489a44a4a0d28dcfa6ad3e24d7d3b6e233a56e12eab59b3f'
    need(hashlib.sha256(config_bytes).hexdigest()==expected,'Native runtime config changed; cold device budget invalid')
    need(stat.S_ISREG(tools_metadata.st_mode) and tools_metadata.st_uid==1204 and tools_metadata.st_size>0,
         'Expected existing ordinary tools disk; cannot apply one-device budget')
    return {'freshRootfsDevicesUpperBound':1,'toolsUblkDevices':0,'restoreMemoryDevices':0,
            'additionalCaptureDevices':0,'headroomSlots':2,'requiredFreeSlots':3,
            'conditions':'Fixed installed config, ordinary tools file, cold start, no extra drives, no restore and startup prewarm disabled',
            'scope':'Source-derived request demand with headroom, not a reservation against concurrent allocators'}

def capacity():
    config=read(BASE/'config/runtime.toml')
    tools=safe(BASE/'deps/tools/0.1.1/tools.ext4')
    need(tools.resolve(strict=True)==tools,'Tools path redirected')
    budget=cold_device_budget(config,tools.stat())
    module=Path('/sys/module/ublk_drv');devices=Path('/sys/class/ublk-char')
    limit=int((module/'parameters/ublks_max').read_text().strip())
    ids=sorted(int(p.name[5:]) for p in devices.iterdir() if re.fullmatch(r'ublkc[0-9]+',p.name))
    need(0<limit<=4096 and len(ids)<=limit,'Unexpected ublk inventory')
    return dict(budget,deviceLimit=limit,existingDeviceCount=len(ids),freeSlots=limit-len(ids))

def confirm_v1_precreate_stop():
    previous=json.loads(read(ROOT/'relay/reports/node-a-native-parent-3_n919hz/return.json'))
    need(previous.get('revision')=='native-runtime-parent-v1'
         and previous.get('run_id')=='aa22f9bff14949f087c3ffcd70b807e8'
         and previous.get('status')=='STOPPED_NATIVE_RUNTIME_PARENT_PRESERVE_RECEIPTS'
         and previous.get('createCalls')==0 and previous.get('snapshotCaptureCalls')==0
         and previous.get('parentId') is None and previous.get('snapshotId') is None
         and previous.get('createOutcomeUncertain') is False and previous.get('SDK_called') is False
         and previous.get('error',{}).get('reason')=='Insufficient free ublk slots; do not stop old services or free other devices',
         'Prior attempt is not the confirmed pre-create capacity stop; preserve it')
    return {'priorRunId':previous['run_id'],'priorCreateCalls':0,'oldReportPreserved':True}


def find_own(api,run):
    query='/v2/sandboxes?'+urlencode({'metadata':'cow_parent_run='+run,'limit':2})
    status,rows=api.call('GET',query)
    need(status==200 and isinstance(rows,list) and len(rows)<=1,'Own request reconciliation not unique')
    if not rows:return None
    row=rows[0];sid=row.get('sandboxID')
    need(isinstance(sid,str) and ID.fullmatch(sid) and row.get('metadata',{}).get('cow_parent_run')==run,'Reconciled sandbox ownership differs')
    return sid

def delete_own(api,sid,run):
    status,body=api.call('GET','/sandboxes/'+sid)
    if status==404:return True
    need(status==200 and isinstance(body,dict) and body.get('metadata',{}).get('cow_parent_run')==run,'Own sandbox ownership changed; no delete')
    status,_=api.call('DELETE','/sandboxes/'+sid,timeout=90)
    need(status in (200,204,404),'Own delete not acknowledged')
    return api.call('GET','/sandboxes/'+sid)[0]==404

def main():
    global PORT
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:
        print(json.dumps({'status':'PLAN_ONLY','maxColdCreateCalls':1,'memoryMiB':512,'SDK_called':False,
            'sharedRootfsEnabled':False,'imageDownloadPermitted':False,'servicesChanged':False},indent=2));return 0
    need(sys.platform=='linux' and socket.gethostname()=='server1' and os.uname().machine=='aarch64','Use A ARM64')
    need(os.getuid()==os.geteuid()==1204 and os.getgid()==os.getegid()==1205,'Use ordinary jwk')
    caps=re.findall(r'^(Cap(?:Inh|Prm|Eff|Amb)):\s*(\w+)$',Path('/proc/self/status').read_text(),re.M)
    need(len(caps)==4 and all(int(v,16)==0 for k,v in caps),'Capability-free coordinator required')
    need(os.environ.get('HOME')=='/home/jwk','Keep normal HOME')
    os.umask(0o077)
    import fcntl
    with open(safe(ROOT/'relay/native-runtime-parent-node-a.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if PENDING.exists():
            print('EXISTING_NATIVE_PARENT_RECEIPT_NO_NEW_CREATE\n'+read(PENDING).decode());return 1
        work=Path(tempfile.mkdtemp(prefix='node-a-native-parent-',dir=safe(ROOT/'relay/reports')))
        report={'revision':'native-runtime-parent-v2','run_id':uuid.uuid4().hex,'reportDirectory':str(work),
            'SDK_called':False,'servicesChanged':False,'sharedRootfsEnabled':False,'memfileCrossNodeCowAccepted':False,
            'imageDownloaded':False,'maxColdCreateCalls':1,'createCalls':0,'snapshotCaptureCalls':0,
            'parentId':None,'snapshotId':None,'parentDeleted':False,'createOutcomeUncertain':False,
            'cpuCount':1,'memoryMiB':512,'diskPolicy':'inherit source virtual size, no shrinking',
            'scope':'New Runtime ordinary rootfs/cold-start/workload/capture input preparation; no sharing benefit claim'}
        api=None;env={};intent=False
        try:
            report['previousAttempt']=confirm_v1_precreate_stop()
            definition_raw=read(BASE/'definition-native.json')
            need(hashlib.sha256(definition_raw).hexdigest()=='b7202599c86d5a3242ff00c20eee0b39ff885e638d17fdaadacf40793522f410','Verified native definition changed')
            definition=json.loads(definition_raw)
            need(definition.get('rootfsBinding') is None,'This initial Runtime baseline requires UB binding disabled')
            PORT=definition['apiPort'];need(type(PORT) is int and 18082<=PORT<=18089,'Native API port differs')
            launcher=BASE/'libexec/native_service.py'
            need(hashlib.sha256(read(launcher)).hexdigest()=='13b39c2578120e02c8dea903d0d3ed43506afc3a9da58623e54088805526890f','Installed launcher changed')
            print('PHASE=native_health_post_disconnect_no_proxy_restart',flush=True)
            with (work/'health.log').open('xb') as log:
                result=subprocess.run([sys.executable,'-I','-B',str(launcher),'health','--post-disconnect'],stdout=log,stderr=subprocess.STDOUT,timeout=120)
            health_text=read(work/'health.log').decode(errors='replace')
            need(result.returncode==0,'Post-disconnect health failed; preserve health.log; no Guest attempted')
            health=json.loads(health_text.split('BEGIN_NATIVE_HEALTH_REPORT\n',1)[1].split('\nEND_NATIVE_HEALTH_REPORT',1)[0])
            need(health.get('post_disconnect') is True and health.get('nativeGuestBindingsConfigured') is False,'Expected stable sharing-disabled Runtime')
            report['health']=health
            inventory=capacity();report['ublkCapacity']=inventory
            need(inventory['freeSlots']>=inventory['requiredFreeSlots'],'Insufficient free ublk slots; do not stop old services or free other devices')
            limits=subprocess.check_output(['/usr/bin/systemctl','show',UNIT,'--property=LimitMEMLOCK','--value'],text=True,timeout=10).strip()
            need(limits.isdigit() and int(limits)>=2147483648,'New unit memlock prerequisite differs')
            need(os.statvfs(ROOT).f_bavail*os.statvfs(ROOT).f_frsize>=8*1024**3,'Need 8GiB free workspace disk')
            api=Api();report['runtimeIdentity']=api.identity;report['apiPort']=PORT
            need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'New Runtime already has a sandbox; do not start another')
            print('PHASE=verify_existing_PyPika_OCI_no_download',flush=True)
            report['imageVerification']=verify_layout(OCI,IMAGE_SHA)
            for name in ('tmp','cache','cli-config/aenv'):(work/name).mkdir(parents=True)
            env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8',
                 'PATH':str(BASE/'native/bin')+':/usr/bin:/bin','LD_LIBRARY_PATH':str(BASE/'native/lib')+':'+str(BASE/'native/fallback/lib'),
                 'TMPDIR':str(work/'tmp'),'XDG_CACHE_HOME':str(work/'cache'),'XDG_CONFIG_HOME':str(work/'cli-config'),
                 'NO_PROXY':'127.0.0.1,localhost,::1','no_proxy':'127.0.0.1,localhost,::1'}
            report['ublkImmediatelyBeforeCreate']=capacity()
            need(report['ublkImmediatelyBeforeCreate']['freeSlots']>=report['ublkImmediatelyBeforeCreate']['requiredFreeSlots'],
                 'ublk capacity changed during preparation; no request sent')
            # Persist one intent before the only cold-create request.
            report.update(createCalls=1,createOutcomeUncertain=True)
            with PENDING.open('x') as stream:json.dump(report,stream);stream.flush();os.fsync(stream.fileno())
            intent=True
            print('PHASE=one_new_Runtime_cold_sandbox_no_UB',flush=True)
            status,body=api.call('POST','/sandboxes-cold',{'image':'ocidir://'+str(OCI)+'@'+IMAGE_SHA,
                'cpuCount':1,'memoryMB':512,'secure':True,'autoPause':False,'allowInternetAccess':False,
                'timeout':900,'metadata':{'cow_parent_run':report['run_id']}},timeout=600)
            report['createHttpStatus']=status
            if status!=201:report['createError']=error_summary(body,api.key)
            need(status==201 and isinstance(body,dict),'Cold create not confirmed; no retry')
            sid=body.get('sandboxID');need(isinstance(sid,str) and ID.fullmatch(sid),'Created sandbox identity missing')
            report.update(parentId=sid,createOutcomeUncertain=False,diskLogicalMiBObserved=body.get('diskSizeMB'))
            save(PENDING,report)
            credentials=work/'cli-config/aenv/credentials'
            credentials.write_text('url = "http://127.0.0.1:'+str(PORT)+'"\napi_key = '+json.dumps(api.key)+'\n')
            print('PHASE=Guest_PyPika_import',flush=True)
            checked_process([BASE/'bin/aenv','exec',sid,'python','-c',
                'import os,importlib; os.chdir("/pypika"); importlib.import_module("pypika"); print("NATIVE_PARENT_PYPIKA_OK")'],env,work/'guest-import.log',60)
            need(b'NATIVE_PARENT_PYPIKA_OK' in read(work/'guest-import.log'),'Guest workload import did not confirm')
            report['guestWorkloadPassed']=True
            report['snapshotCaptureCalls']=1;save(PENDING,report)
            print('PHASE=capture_new_Runtime_parent_snapshot',flush=True)
            status,body=api.call('POST','/sandboxes/'+sid+'/snapshots',{'name':'native-parent-'+report['run_id']},timeout=300)
            report['snapshotHttpStatus']=status
            if status not in (200,201):report['snapshotError']=error_summary(body,api.key)
            need(status in (200,201) and isinstance(body,dict),'Snapshot capture not confirmed; preserve receipt')
            snapshot=body.get('snapshotID');need(isinstance(snapshot,str) and ID.fullmatch(snapshot),'Snapshot ID missing')
            report['snapshotId']=snapshot;report['layerInventory']=parent_layer_inventory(snapshot);save(PENDING,report)
        except Exception as error:
            report['error']={'type':type(error).__name__,'reason':str(error)[:1200] if isinstance(error,RuntimeError) else 'Inspect bounded own logs; no retry'}
            if isinstance(error,ChildFailure):report['error']['childDiagnostics']=error.diagnostics
            if 'health_text' in locals() and not report.get('health'):report['healthLogTail']=redact_child_output(health_text[-8000:],{})
        finally:
            if intent and api and report['parentId'] is None:
                try:
                    sid=find_own(api,report['run_id'])
                    if sid:report['parentId']=sid;report['createOutcomeUncertain']=False
                    else:report['reconciliation']='No visible matching sandbox now; late completion remains possible'
                except Exception as error:report['reconciliationError']=type(error).__name__
            if report['parentId'] and api:
                sid=report['parentId'];report['firecrackerLogs']=collect_fc_logs(sid,env,api.key)
                try:report['parentDeleted']=delete_own(api,sid,report['run_id'])
                except Exception as error:report['cleanupError']={'type':type(error).__name__,'reason':str(error)[:500] if isinstance(error,RuntimeError) else 'Preserve pending'}
            credentials=work/'cli-config/aenv/credentials'
            if credentials.exists():credentials.unlink()
            report['temporaryCredentialsRemoved']=not credentials.exists()
            try:report['ublkAfter']=capacity()
            except Exception as error:report['ublkAfter']={'available':False,'errorType':type(error).__name__}
        passed=bool(report['snapshotId'] and report['parentDeleted'] and report.get('guestWorkloadPassed') and not report.get('error'))
        report['status']='NATIVE_RUNTIME_PARENT_CAPTURED_GUEST_RELEASED_UB_DISABLED' if passed else 'STOPPED_NATIVE_RUNTIME_PARENT_PRESERVE_RECEIPTS'
        save(work/'return.json',report)
        if intent:save(PENDING,report)
        print('BEGIN_NATIVE_RUNTIME_PARENT_REPORT\n'+json.dumps(report,indent=2)+'\nEND_NATIVE_RUNTIME_PARENT_REPORT',flush=True)
        return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
