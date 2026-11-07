"""Read-only reconciliation evidence. Never edit state, signal processes or rerun a build."""
import hashlib,json,os,pathlib,platform,re,time
P=pathlib.Path
STATE=P('/home/jwk/y-aenv-control/relay')
BASES=(P('/data/jwk/aenv-y-20261107'),P('/data/jwk/aenv-y-ae9c626-20261107'))
SELF_JOB='y-unconfirmed-readonly-20261107-004-node-y'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def redact(raw):
    text=raw.decode(errors='replace')
    text=re.sub(r'\b(?:github[_]pat[_]|gh[pousr]_)[A-Za-z0-9_]+','[REDACTED]',text)
    text=re.sub(r'(?im)(authorization\s*[:=]\s*)(?:bearer|token|basic)\s+\S+',r'\1[REDACTED]',text)
    return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',text)
def metadata(path):
    if not path.exists():return {'exists':False}
    if path.is_symlink():return {'symlink':True,'not_read':True}
    s=path.stat();return {'exists':True,'bytes':s.st_size,'uid':s.st_uid,'mtime_ns':s.st_mtime_ns}
def json_file(path,keys):
    out=metadata(path)
    if not out.get('exists') or out.get('symlink'):return out
    if out['bytes']>512*1024:return {**out,'read':'size_bound_exceeded'}
    try:
        raw=path.read_bytes();value=json.loads(raw)
        out.update(sha256=sha(raw),selected={k:value[k] for k in keys if k in value})
    except Exception as e:out['error_type']=type(e).__name__
    return out
def tail(path,limit=16000):
    out=metadata(path)
    if not out.get('exists') or out.get('symlink'):return out
    with path.open('rb') as f:
        f.seek(max(0,out['bytes']-limit));raw=f.read(limit)
    out['tail']=redact(raw);out['tail_bytes']=len(raw);return out
def is_under(path,root):
    return path==str(root) or path.startswith(str(root)+'/')
def main():
    assert os.geteuid()==0
    report={'action':'Y_READONLY_UNCONFIRMED_TASK_DIAGNOSIS','time_unix':time.time(),
      'hostname':platform.node(),'kernel':platform.release(),
      'boot_id':P('/proc/sys/kernel/random/boot_id').read_text().strip(),
      'jobs':[],'builds':[],'related_processes':[],'process_races':0,'state_mutated':False,'signals_sent':False}
    directories=sorted((STATE/'jobs').iterdir())
    assert len(directories)<=64
    for directory in directories:
        if not directory.is_dir() or directory.is_symlink() or directory.name==SELF_JOB:continue
        row={'job_id':directory.name,
          'state':json_file(directory/'state.json',('state','jobSha256','identity','startedUnixNs','exitCode')),
          'report':json_file(directory/'report.json',('state','jobSha256','identity','exitCode','elapsedSeconds')),
          'task_source':metadata(directory/'task.py')}
        if (directory/'task.py').is_file() and not (directory/'task.py').is_symlink():
            row['task_source']['sha256']=sha((directory/'task.py').read_bytes())
        row['stdout']=tail(directory/'stdout.log');row['stderr']=tail(directory/'stderr.log')
        report['jobs'].append(row)
    for base in BASES:
        row={'base':str(base),'status':json_file(base/'build-status.json',
          ('schema','action','source_commit','compiled','state','reason','error_type','jwk_uid','kernel',
           'source_archive_sha256','startup_patch_applied','source_modifications','modified_files',
           'applied_patch_sha256','original_source_unchanged_after_build','binaries','stages')),
          'stage_logs':[]}
        logs=base/'build-logs'
        if logs.is_dir() and not logs.is_symlink():
            files=sorted(logs.iterdir(),key=lambda p:p.stat().st_mtime_ns,reverse=True)
            for path in files[:6]:
                if path.is_file() and not path.is_symlink():row['stage_logs'].append({'name':path.name,**tail(path,10000)})
        report['builds'].append(row)
    for proc in P('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            args=(proc/'cmdline').read_bytes().decode(errors='replace').split('\0')
            cwd=str((proc/'cwd').resolve());exe=str((proc/'exe').resolve())
            linked_args=[a for a in args if a.startswith(str(STATE/'jobs')+'/') or any(is_under(a,b) for b in BASES)]
            related=bool(linked_args) or any(is_under(cwd,b) or is_under(exe,b) for b in BASES)
            if not related:continue
            data=(proc/'stat').read_text();fields=data.rsplit(')',1)[1].split()
            report['related_processes'].append({'pid':int(proc.name),'uid':proc.stat().st_uid,
              'comm':(proc/'comm').read_text().strip(),'exe':exe,'cwd':cwd,'status':fields[0],
              'ppid':int(fields[1]),'process_group':int(fields[2]),'session':int(fields[3]),
              'start_ticks':int(fields[19]),'user_ticks':int(fields[11]),'system_ticks':int(fields[12]),
              'related_local_path_args':linked_args[:6],
              'cgroup':(proc/'cgroup').read_text()[:1000]})
        except (OSError,ValueError,IndexError):report['process_races']+=1
    report['related_processes']=report['related_processes'][:160]
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
