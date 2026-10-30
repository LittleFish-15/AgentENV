"""C owned-failure recovery and dedicated-group functional continuation.

Requires specific approval for reserving the experiment group and normal
inactive device4 deletion. No module switch or unrelated service operation.
"""
import argparse
import inspect
import base64
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
try:
    import grp
    import pwd
except ImportError:  # Local Windows plan/logic checks only.
    grp=pwd=None
import re
import stat
import sys
import time
import uuid
import zlib
from datetime import datetime

TRANSPORT='C_NATIVE_ADAPTER_BUILD_OBMM_SWITCH_EXPLICIT_RESTORE'
SCOPE='C_T1_DEDICATED_GROUP_RECOVER_OWN_INACTIVE_DEVICE_AND_CONTINUE'
REPAIR=Path('/var/lib/agentenv-hpc1-repair-v1')
OLD=Path('/var/lib/agentenv-hpc1')
NEW=Path('/var/lib/agentenv-hpc2')
PARENT=Path('/var/lib/agentenv-c-rootfs-preflight-v1')
GROUP='aenv-hpc1-exp'
DRIVER=Path('/var/lib/agentenv-root-relay/jobs/root-c-t1-scoped-004/driver.py')
DRIVER_SHA='9de59dfe89ba543498d168be57128769fb7e6fadfa9ac7d9c779675f40e657ea'
DIAGNOSTIC_SHA='b9a66ed299da4245041ced90b97ab3a813a5ad80895d027d34cd83310b0b81f5'
RETIRE='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'
RETIRE_SHA='a3a43280b4912a970e8290bf776ffe617df83540aa2e675d110d73bbcf2012d3'
AUTH_SOURCE='IiIiUHJlLVNUQVJUIGF0dHJpYnV0aW9uIGNvbnRyYWN0IGZvciBhIHNlcGFyYXRlbHkgcmVzZXJ2ZWQgZXhwZXJpbWVudCBncm91cC4KClRoZSBjYWxsZXIgbXVzdCByZXNlcnZlIHRoZSBncm91cCwga2VlcCBpdHMgbWVtYmVyc2hpcCBlbXB0eSwgbGF1bmNoIG9ubHkgdGhlCm93bmVkIFJ1bnRpbWUgd2l0aCB0aGF0IHByaW1hcnkgR0lELCBhbmQgdmVyaWZ5IGFsbCBob2xkZXJzIG9uIGV2ZXJ5IGNoZWNrLgpUaGlzIG1vZHVsZSBkb2VzIG5vdCBjcmVhdGUgZ3JvdXBzLCBncmFudCBwZXJtaXNzaW9ucyBvciBkZWxldGUgZGV2aWNlcy4KIiIiCgpkZWYgYXR0cmlidXRlKGluZm8sICosIHJlc2VydmVkX2dpZCwgb3duZWRfdW5pdHMsIHByb2Nlc3NlcywgZ3JvdXBfbWVtYmVycywKICAgICAgICAgICAgICBzY2FuX2NvbXBsZXRlLCBleGVjdXRhYmxlX2hhc2hlcyk6CiAgICBpZiBub3Qgc2Nhbl9jb21wbGV0ZSBvciBncm91cF9tZW1iZXJzIG9yIHJlc2VydmVkX2dpZCBpbiAoMCwxMjA1KToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCdEZWRpY2F0ZWQgZ3JvdXAgaXNvbGF0aW9uIG5vdCBlc3RhYmxpc2hlZCcpCiAgICBpZiBpbmZvWyd1aWQnXSE9MTIwNCBvciBpbmZvWydnaWQnXSE9cmVzZXJ2ZWRfZ2lkOgogICAgICAgIHJldHVybiBOb25lCiAgICBtZW1iZXJzPVtwIGZvciBwIGluIHByb2Nlc3NlcyBpZiByZXNlcnZlZF9naWQgaW4gcFsnYWxsR2lkcyddXQogICAgaWYgbm90IG1lbWJlcnM6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcignRGVkaWNhdGVkIGdyb3VwIGhhcyBubyB2ZXJpZmllZCBsaXZlIG93bmVyJykKICAgIGZvciBwIGluIG1lbWJlcnM6CiAgICAgICAgaWYgKG5vdCBwWydzdGFibGUnXSBvciBwWyd1aWRzJ10hPVsxMjA0XSo0IG9yIHBbJ3VuaXQnXSBub3QgaW4gb3duZWRfdW5pdHMKICAgICAgICAgICAgICAgIG9yIHBbJ3VuaXRJZGVudGl0eSddIT1vd25lZF91bml0c1twWyd1bml0J11dKToKICAgICAgICAgICAgcmFpc2UgVmFsdWVFcnJvcignRGVkaWNhdGVkIGdyb3VwIGVzY2FwZWQgdGhlIGV4cGVyaW1lbnQnKQogICAgZGFlbW9ucz1bcCBmb3IgcCBpbiBtZW1iZXJzIGlmIHBbJ3ByaW1hcnlHaWQnXT09cmVzZXJ2ZWRfZ2lkCiAgICAgICAgICAgICBhbmQgcFsnZXhlY3V0YWJsZVNoYTI1NiddIGluIGV4ZWN1dGFibGVfaGFzaGVzXQogICAgaWYgbGVuKGRhZW1vbnMpIT0xOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoJ0V4cGVjdGVkIGV4YWN0bHkgb25lIGF0dHJpYnV0YWJsZSBkYWVtb24nKQogICAgb3duZXI9ZGFlbW9uc1swXQogICAgaWYgaW5mb1sncGlkJ109PS0xOgogICAgICAgIGlmIGluZm9bJ3N0YXRlJ10hPTA6cmFpc2UgVmFsdWVFcnJvcignVW5zdGFydGVkIFBJRCBpbiB1bmV4cGVjdGVkIHN0YXRlJykKICAgIGVsaWYgaW5mb1sncGlkJ10hPW93bmVyWydwaWQnXToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCdTdGFydGVkIGRldmljZSBkYWVtb24gZGlmZmVycycpCiAgICByZXR1cm4geydwaWQnOm93bmVyWydwaWQnXSwndGlja3MnOm93bmVyWyd0aWNrcyddLCd1bml0Jzpvd25lclsndW5pdCddLAogICAgICAgICAgICAna2VybmVsT3duZXJHaWQnOnJlc2VydmVkX2dpZCwna2VybmVsUGlkS25vd24nOmluZm9bJ3BpZCddPjB9Cg=='

def need(value,message):
    if not value:raise RuntimeError(message)

def read_root(path,limit=524288):
    need(path.resolve()==path,'Root evidence redirected')
    s=path.stat();need(s.st_uid==0 and not s.st_mode&0o022 and stat.S_ISREG(s.st_mode) and s.st_size<=limit,'Untrusted root evidence')
    return path.read_bytes()

def process_rows(m, gid=None, unit_name=None):
    """Bounded complete credential scan; no process arguments or environments."""
    out=[];end=time.monotonic()+15
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        need(time.monotonic()<end,'Credential scan timed out; no attribution')
        try:
            start=m.ticks(int(proc.name));status=(proc/'status').read_text()
            fields={line.split(':',1)[0]:line.split(':',1)[1].split() for line in status.splitlines() if ':' in line}
            uids=list(map(int,fields['Uid']));gids=set(map(int,fields['Gid']+fields.get('Groups',[])))
            if gid is not None:
                # Threads can have distinct credentials; inspect all, not just leaders.
                for task in (proc/'task').iterdir():
                    try:
                        lines=(task/'status').read_text().splitlines()
                        for line in lines:
                            if line.startswith(('Gid:','Groups:')):gids.update(map(int,line.split()[1:]))
                    except (FileNotFoundError,ProcessLookupError):continue
            groups=[line.split(':',2)[2] for line in (proc/'cgroup').read_text().splitlines()]
            if gid is not None and gid not in gids:continue
            if unit_name is not None and not any(x.endswith('/'+unit_name) for x in groups):continue
            need(m.ticks(int(proc.name))==start,'Credential owner changed')
            out.append({'pid':int(proc.name),'ticks':start,'uids':uids,'allGids':sorted(gids),
                'primaryGid':int(fields['Gid'][0]),'cgroups':groups,'executable':os.readlink(proc/'exe'),'stable':True})
        except (FileNotFoundError,ProcessLookupError):continue
    return out

def save(api,state,phase):
    state['phase']=phase;api.atomic(REPAIR/'journal.json',state)
    print('REPAIR_PHASE='+phase,flush=True)

def query(m,number):
    r=m.command([str(OLD/'ublk-owner-query'),str(number)],2)
    need(r.returncode==0,'Device ownership query failed')
    return json.loads(r.stdout)

def inactive_four(info):
    return info=={'id':4,'uid':1204,'gid':1205,'pid':-1,'state':0}

def normal_recovery(m,api,state):
    diagnostic=json.loads(read_root(PARENT/'maintenance-activate-v1.json'))
    canonical=json.dumps(diagnostic,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    need(hashlib.sha256(canonical).hexdigest()==DIAGNOSTIC_SHA,'Approved reconciliation evidence changed')
    m.write(REPAIR/'reconciliation-evidence.json',(json.dumps(diagnostic,indent=2)+'\n').encode())
    m.load_baseline();m.verify_baseline()
    old_raw=read_root(OLD/'journal.json');old=json.loads(old_raw)
    need(old['runId']==diagnostic['runId'] and old['unknownCreate']=={'attempt':0,'variant':'original'}
         and not old['SDK_called'] and not old['guestHistory'],'Unexpected prior operation; preserve')
    unit=old['units']['original'];demo=m.Demo(old,{},api);demo.bound('original')
    need(demo.inventory('original')==[],'Prior Runtime has consumers; preserve')
    # Require the actual terminal failed operation for this run, not an empty inventory alone.
    log=read_root(OLD/'original.log',1024*1024).decode('utf-8','replace')
    log=re.sub(r'\x1b\[[0-9;]*m','',log)
    failed=[line for line in log.splitlines() if 'failed to start sandbox' in line and 'Permission denied' in line and '/dev/ublkc4' in line]
    need(len(failed)==1 and 'sandbox_id=' in failed[0],'Missing unique terminal failure evidence')
    sid=re.search(r'sandbox_id=([0-9a-f-]{36})',failed[0]);need(sid is not None,'Failed sandbox ID missing')
    info=query(m,4);need(inactive_four(info),'Inactive device4 identity changed')
    need(not Path('/dev/ublkb4').exists() and not Path('/sys/class/block/ublkb4').exists(),'Device4 has become a block device; preserve')
    owned=process_rows(m,unit_name=unit['name'])
    expected_pids={x['pid']:x['ticks'] for x in diagnostic['ownedProcesses']}
    need({x['pid']:x['ticks'] for x in owned}==expected_pids and all(x['uids']==[1204]*4 for x in owned),
         'Prior Runtime process set changed; preserve')
    need(all(Path(x['executable']).name in ('server','uvm-ublk-daemon') for x in owned),'Unexpected FC/consumer present')
    protected={name:m.device_meta(Path('/dev')/name) for name in m.ublk_devices() if name!='ublkc4'}
    need(all(name in protected for name in ('ublkb0','ublkb1','ublkb2','ublkb3','ublkc0','ublkc1','ublkc2','ublkc3')),'Protected inventory changed')
    inode=Path('/dev/ublkc4').stat()
    daemon_path=m.WORK/'original/logs/ublk.log'
    need(daemon_path.resolve()==daemon_path and daemon_path.stat().st_size<=1024*1024,'Daemon log redirected or oversized')
    daemon_log=daemon_path.read_text()
    daemon_log=re.sub(r'\x1b\[[0-9;]*m','',daemon_log)
    additions=[line for line in daemon_log.splitlines() if 'device has been added to ublkdrv' in line and re.search(r'dev_id=4(?:\s|$)',line)]
    need(len(additions)==1,'Device4 creation generation ambiguous')
    start_time=datetime.fromisoformat(additions[0].split()[0].replace('Z','+00:00')).timestamp()
    failed_time=datetime.fromisoformat(failed[0].split()[0].replace('Z','+00:00')).timestamp()
    need(start_time-1<=inode.st_ctime<=failed_time+1,'Device4 inode changed since attributed failure; preserve')
    state.update(previousRunId=old['runId'],failedSandboxId=sid.group(1),previousUnit=unit,
        protectedDevices=protected,inactiveDevice={'inode':inode.st_ino,'rdev':inode.st_rdev,'info':info},
        previousJournalSha256=hashlib.sha256(old_raw).hexdigest())
    m.write(REPAIR/'previous-journal.json',old_raw)
    save(api,state,'prior_failure_attributed_before_stop')
    # Stop only the bound, failed experiment unit; pending is still retained.
    demo.stop('original')
    need(not process_rows(m,unit_name=unit['name']),'Owned unit still has processes')
    need(query(m,4)==info,'Device4 changed after own Runtime exit')
    now=Path('/dev/ublkc4').stat();need((now.st_ino,now.st_rdev)==(inode.st_ino,inode.st_rdev),'Device4 path reused')
    raw=zlib.decompress(base64.b64decode(RETIRE,validate=True));need(hashlib.sha256(raw).hexdigest()==RETIRE_SHA,'Retirement helper differs')
    helper=REPAIR/'retire-inactive4';m.write(helper,raw,mode=0o700)
    state['normalDeleteAttempted']=True;save(api,state,'normal_device4_delete_intent_no_retry')
    result=m.command([str(helper),'4',str(inode.st_ino),str(inode.st_rdev)],10)
    api.atomic(REPAIR/'device4-delete-response.json',{'exitCode':result.returncode,'stdout':result.stdout.decode('utf-8','replace'),'stderr':result.stderr.decode('utf-8','replace')})
    need(result.returncode==0 and json.loads(result.stdout)=={'deviceId':4,'normalDeleteAcknowledged':True,'force':False},
         'Normal delete unconfirmed; preserve intent and do not retry')
    need(not Path('/dev/ublkc4').exists() and 'ublkc4' not in m.ublk_devices(),'Device4 absence not confirmed; no continuation')
    for name,meta in protected.items():need(m.device_meta(Path('/dev')/name)==meta,'Protected device changed; stop')
    state['device4DeleteAcknowledged']=True;save(api,state,'normal_device4_delete_confirmed')
    old['unknownCreate']=False;old['Guest_created']=False
    old['creationReconciliation']={'outcome':'terminal_start_failure','sandboxId':sid.group(1),'device4DeleteAcknowledged':True,
        'ownUnitExited':True,'noFcObserved':True,'inventoryEmpty':True,'evidence':str(REPAIR)}
    demo.restore_acl();old['phase']='original_failed_create_reconciled_owned_resources_released'
    api.atomic(OLD/'journal.json',old);api.atomic(OLD/'report.json',old)
    state['priorResourcesReleased']=True;save(api,state,'prior_owned_failure_released')

def reserve_group(m,api,state):
    try:grp.getgrnam(GROUP)
    except KeyError:pass
    else:raise RuntimeError('Dedicated group already exists; do not reuse an unknown reservation')
    save(api,state,'group_create_intent')
    m.checked([m.tool('groupadd'),'--system',GROUP])
    group=grp.getgrnam(GROUP)
    state['group']={'name':GROUP,'gid':group.gr_gid,'retainedForAudit':True}
    save(api,state,'group_created_reserved')
    need(not group.gr_mem and group.gr_gid not in (0,1205,985,36),'Dedicated group is not exclusive')
    need(not any(p.pw_gid==group.gr_gid for p in pwd.getpwall()),'Group is a user primary group')
    need(not process_rows(m,gid=group.gr_gid),'Group already has processes; preserve reservation')
    return group.gr_gid

def configure_continuation(m,api,repair,gid):
    m.ROOT=NEW;m.SCOPE=SCOPE
    m.BASELINE_DEVICES=list(repair['protectedDevices'].values())
    # All existing devices are protected; v9's original owner remains checked.
    m.load_baseline()
    m.BASELINE_DEVICES=list(repair['protectedDevices'].values())
    old_folder=m.folder;old_write=m.write
    def folder(path,uid=0,gid=0,mode=0o700):
        if path.exists() and (path.is_relative_to(m.WORK) or path.is_relative_to(NEW)):
            s=path.stat();need(path.resolve()==path and path.is_dir() and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==mode,'Existing work directory differs');return
        old_folder(path,uid,gid,mode)
    def write(path,data,uid=0,gid=0,mode=0o600):
        if path.exists() and (path.is_relative_to(m.WORK) or path.is_relative_to(NEW)):
            s=path.stat();need(path.resolve()==path and s.st_uid==uid and stat.S_ISREG(s.st_mode)
                 and s.st_gid==gid and stat.S_IMODE(s.st_mode)==mode and path.read_bytes()==data,'Existing work file differs; preserve');return
        old_write(path,data,uid,gid,mode)
    m.folder=folder;m.write=write
    # Avoid rebuilding/copying payloads. prepare_sources only needs idempotent
    # links for already verified exact source inodes under this experiment.
    preparation=inspect.getsource(m.prepare_sources)
    guard="need(not config.exists(),'Unreviewed dependency config preserved')"
    need(preparation.count(guard)==1,'Unexpected fixed preparation implementation')
    preparation=preparation.replace(guard,"need(not config.is_symlink(),'Dependency config redirected')")
    # Existing config still passes the exact-byte/uid/gid/mode write guard above.
    exec(compile(preparation,'<fixed-preparation-exact-reuse>','exec'),m.__dict__)
    original_prepare=m.prepare_sources
    def prepare():
        link=os.link
        def same_link(source,target):
            if Path(target).exists():
                need(Path(target).is_relative_to(m.WORK) and Path(target).resolve()==Path(target)
                     and os.path.samestat(Path(source).stat(),Path(target).stat()),'Existing dependency differs');return
            link(source,target)
        os.link=same_link
        try:original_prepare()
        finally:os.link=link
    m.prepare_sources=prepare
    old_launch=m.Demo.launch
    def launch(self,label,argv,properties):
        if label in ('original','dax'):
            properties=[('Group='+str(gid)) if p=='Group=1205' else
                        ('SupplementaryGroups=1205 985 36') if p=='SupplementaryGroups=985 36' else p for p in properties]
        return old_launch(self,label,argv,properties)
    m.Demo.launch=launch
    auth={};exec(compile(base64.b64decode(AUTH_SOURCE),'<prestart-attribution>','exec'),auth)
    original_permissions=m.ScopedDevicePermissions
    def audit_owner(demo,variant):
        group=grp.getgrnam(GROUP);need(group.gr_gid==gid,'Reserved group changed')
        units={r['name']:r['description'] for v,r in demo.state['units'].items() if v in ('original','dax') and not r.get('stopped')}
        rows=process_rows(m,gid=gid)
        expected=m.PINS['artifacts/'+variant+'/bin/uvm-ublk-daemon']
        for row in rows:
            names=[u for u in units if any(c.endswith('/'+u) for c in row['cgroups'])]
            row['unit']=names[0] if len(names)==1 else ''
            row['unitIdentity']=m.unit(row['unit'])['Description'] if row['unit'] else None
            row['executableSha256']=''
            if Path(row['executable']).name=='uvm-ublk-daemon':
                with (Path('/proc')/str(row['pid'])/'exe').open('rb') as stream:
                    s=os.fstat(stream.fileno());row['executableSha256']=hashlib.file_digest(stream,'sha256').hexdigest()
                    row['executableIdentity']=(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                need(m.ticks(row['pid'])==row['ticks'],'Daemon identity changed')
        result=auth['attribute']({'uid':1204,'gid':gid,'pid':-1,'state':0},reserved_gid=gid,
            owned_units=units,processes=rows,group_members=group.gr_mem,scan_complete=True,executable_hashes={expected})
        need(result is not None,'Dedicated Runtime owner missing')
        owner=next(row for row in rows if row['pid']==result['pid'])
        demo.state['permissionOwner']={**owner,'variant':variant}
        demo.mark('dedicated_group_owner_audited_before_create')
    old_runtime=m.Demo.runtime
    def runtime(self,variant):
        old_runtime(self,variant);audit_owner(self,variant)
    m.Demo.runtime=runtime
    class Permissions(original_permissions):
        def authorized_process(self,info):
            if info['uid']!=1204 or info['gid']!=gid:return None
            group=grp.getgrnam(GROUP);need(group.gr_gid==gid and not group.gr_mem,'Reserved group membership changed')
            owner=self.demo.state.get('permissionOwner')
            if owner is None:return None
            # Full group/thread audit precedes POST. On the 1.6s device-open
            # path verify the attested daemon directly, not another global scan.
            unit_row=self.demo.state['units'][owner['variant']]
            need(not unit_row.get('stopped') and m.ticks(owner['pid'])==owner['ticks'],'Attested daemon exited')
            process=Path('/proc')/str(owner['pid'])
            fields={line.split(':',1)[0]:line.split(':',1)[1].split() for line in (process/'status').read_text().splitlines() if ':' in line}
            need(list(map(int,fields['Uid']))==[1204]*4 and list(map(int,fields['Gid']))==[gid]*4,'Daemon credentials changed')
            need(any(line.split(':',2)[2].endswith('/'+owner['unit']) for line in (process/'cgroup').read_text().splitlines()),'Daemon cgroup changed')
            s=(process/'exe').stat()
            need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==tuple(owner['executableIdentity']),'Daemon executable changed')
            need((info['pid']==-1 and info['state']==0) or info['pid']==owner['pid'],'Device owner PID differs')
            return (owner['variant'],owner['ticks'])
        def consider(self,name):
            # Parent checks kernel GID1205 before authorization. Adapt only that
            # fixed filter using the dedicated source below, not a UID-only bypass.
            return dedicated_consider(self,name)
    namespace=dict(m.__dict__);namespace['EXPERIMENT_GID']=gid
    exec(compile(base64.b64decode('ZGVmIGNvbnNpZGVyKHNlbGYsIG5hbWUpOgogICAgICAgIGlmIG5hbWUgaW4gc2VsZi5wcm90ZWN0ZWQ6cmV0dXJuCiAgICAgICAgcGF0aD1QYXRoKCcvZGV2JykvbmFtZQogICAgICAgIHRyeTpmZD1vcy5vcGVuKHBhdGgsb3MuT19QQVRIfG9zLk9fTk9GT0xMT1d8b3MuT19DTE9FWEVDKQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjpyZXR1cm4KICAgICAgICB0cnk6CiAgICAgICAgICAgIHN0PW9zLmZzdGF0KGZkKQogICAgICAgICAgICBpZiBub3QgKHN0YXQuU19JU0NIUihzdC5zdF9tb2RlKSBpZiBuYW1lLnN0YXJ0c3dpdGgoJ3VibGtjJykgZWxzZSBzdGF0LlNfSVNCTEsoc3Quc3RfbW9kZSkpOnJldHVybgogICAgICAgICAgICBpZGVudGl0eT0oc3Quc3RfZGV2LHN0LnN0X2lubyxzdC5zdF9yZGV2KQogICAgICAgICAgICBpZiBpZGVudGl0eSBpbiBzZWxmLnJlamVjdGVkOnJldHVybgogICAgICAgICAgICBpZiAoc3Quc3RfdWlkLHN0LnN0X2dpZCxzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSkpPT0oMTIwNCwxMjA1LDBvNjAwKTpyZXR1cm4KICAgICAgICAgICAgbnVtYmVyPWludChuYW1lWzU6XSk7cm93PXNlbGYucXVlcnkobnVtYmVyKQogICAgICAgICAgICBpZiByb3dbJ3VpZCddIT0xMjA0IG9yIHJvd1snZ2lkJ10hPUVYUEVSSU1FTlRfR0lEOgogICAgICAgICAgICAgICAgc2VsZi5yZWplY3RlZC5hZGQoaWRlbnRpdHkpO3JldHVybgogICAgICAgICAgICBvd25lcj1zZWxmLmF1dGhvcml6ZWRfcHJvY2Vzcyhyb3cpCiAgICAgICAgICAgIGlmIG93bmVyIGlzIE5vbmU6cmV0dXJuICAjIE5vdCBvdXIgUnVudGltZTsgZG8gbm90IGFsdGVyIGl0LgogICAgICAgICAgICByb3cyPXNlbGYucXVlcnkobnVtYmVyKQogICAgICAgICAgICBpZiBhbnkocm93MltrZXldIT1yb3dba2V5XSBmb3Iga2V5IGluICgnaWQnLCdwaWQnLCd1aWQnLCdnaWQnKSk6cmV0dXJuCiAgICAgICAgICAgIGlmIHNlbGYuYXV0aG9yaXplZF9wcm9jZXNzKHJvdzIpIT1vd25lcjpyZXR1cm4KICAgICAgICAgICAgY3VycmVudD1wYXRoLmxzdGF0KCkKICAgICAgICAgICAgaWYgKGN1cnJlbnQuc3RfZGV2LGN1cnJlbnQuc3RfaW5vLGN1cnJlbnQuc3RfcmRldikhPWlkZW50aXR5OnJldHVybgogICAgICAgICAgICBldmVudD17J2RldmljZSc6bmFtZSwnaW5vZGUnOnN0LnN0X2lubywncmRldic6c3Quc3RfcmRldiwnb3duZXInOnJvdzIsCiAgICAgICAgICAgICAgICAgICAndmFyaWFudCc6b3duZXJbMF0sJ3N0YXJ0VGlja3MnOm93bmVyWzFdLCdwZXJtaXNzaW9uQ2hhbmdlSW50ZW50JzpUcnVlfQogICAgICAgICAgICAjIER1cmFibGUgcGVybWlzc2lvbiBpbnRlbnQgcHJlY2VkZXMgbW9kaWZpY2F0aW9uLiBPX1BBVEggcGlucyB0aGlzIGlub2RlOgogICAgICAgICAgICAjIGRlbGV0aW5nL3JldXNpbmcgdGhlIHBhdGhuYW1lIGNhbm5vdCByZXRhcmdldCBvdXIgY2hvd24vY2htb2QgdG8gYSBuZXcgZGV2aWNlLgogICAgICAgICAgICB3aXRoIChST09ULyd1YmxrLXBlcm1pc3Npb25zLmpzb25sJykub3BlbignYScsZW5jb2Rpbmc9J3V0Zi04JykgYXMgc3RyZWFtOgogICAgICAgICAgICAgICAgc3RyZWFtLndyaXRlKGpzb24uZHVtcHMoZXZlbnQpKydcbicpO3N0cmVhbS5mbHVzaCgpO29zLmZzeW5jKHN0cmVhbS5maWxlbm8oKSkKICAgICAgICAgICAgICAgIHBpbm5lZD0nL3Byb2Mvc2VsZi9mZC8nK3N0cihmZCkKICAgICAgICAgICAgICAgIG9zLmNob3duKHBpbm5lZCwxMjA0LDEyMDUpO29zLmNobW9kKHBpbm5lZCwwbzYwMCkKICAgICAgICAgICAgICAgIGZpbmFsPW9zLmZzdGF0KGZkKQogICAgICAgICAgICAgICAgbmVlZCgoZmluYWwuc3RfdWlkLGZpbmFsLnN0X2dpZCxzdGF0LlNfSU1PREUoZmluYWwuc3RfbW9kZSkpPT0oMTIwNCwxMjA1LDBvNjAwKSwnT3duZWQgZGV2aWNlIHBlcm1pc3Npb24gdXBkYXRlIGZhaWxlZCcpCiAgICAgICAgICAgICAgICBldmVudFsncGVybWlzc2lvbkNoYW5nZUFja25vd2xlZGdlZCddPVRydWUKICAgICAgICAgICAgICAgIHN0cmVhbS53cml0ZShqc29uLmR1bXBzKGV2ZW50KSsnXG4nKTtzdHJlYW0uZmx1c2goKTtvcy5mc3luYyhzdHJlYW0uZmlsZW5vKCkpCiAgICAgICAgICAgIHNlbGYuZ3JhbnRzLmFwcGVuZChldmVudCkKICAgICAgICBmaW5hbGx5Om9zLmNsb3NlKGZkKQ=='),'<dedicated-device-permissions>','exec'),namespace)
    dedicated_consider=namespace['consider']
    m.ScopedDevicePermissions=Permissions
    old_cli=m.Demo.cli
    def cli(self,variant,args,timeout=330):
        result=old_cli(self,variant,args,timeout)
        if args and args[0]=='start':
            key=(m.WORK/variant/'state/secrets/api-key').read_text().strip()
            record={'exitCode':result.returncode,'stdout':result.stdout.decode('utf-8','replace').replace(key,'[REDACTED]'),
                'stderr':result.stderr.decode('utf-8','replace').replace(key,'[REDACTED]')}
            api.atomic(NEW/(variant+'-last-create-response.json'),record)
            self.state['lastCreateResponse']=record
        return result
    m.Demo.cli=cli
    return m

def publish(api,state):
    payload=dict(state)
    if (NEW/'report.json').exists():
        payload['continuation']=json.loads(read_root(NEW/'report.json'))
        for key in ('SDK_called','Guest_created','functionalSmokePassed','unknownCreate','netSavingsBytes'):
            payload[key]=payload['continuation'].get(key)
    payload.update(scope=SCOPE)
    api.atomic(REPAIR/'report.json',payload)
    api.atomic(PARENT/'maintenance-activate-v1.json',payload)
    os.chmod(PARENT/'maintenance-activate-v1.json',0o640)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('plan','activate','restore'));parser.add_argument('--approval');args=parser.parse_args()
    if args.action=='plan':
        print(json.dumps({'scope':SCOPE,'dedicatedGroup':GROUP,'device4NormalDeleteOnly':True,'protectedDevices':'all other existing devices',
            'maxConcurrentGuests':2,'logicalUbBytes':1811939328,'coverageGuardBytes':4294967296,'physicalHardQuota':False,'groupRetainedForAudit':True}));return
    need(os.getuid()==os.geteuid()==0 and args.approval==TRANSPORT,'Explicit root repair approval required')
    expected=json.loads(read_root(PARENT/'receipt.json'))
    need(expected['machineId']==Path('/etc/machine-id').read_text().strip() and expected['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'C identity changed')
    need(expected['kernel']==platform.release() and Path('/sys/module/obmm/srcversion').read_text().strip()=='C2BBB64D75C618180ABA3A6'
         and Path('/sys/module/obmm/parameters/pmem_ro_enable').read_text().strip()=='Y','C kernel/candidate differs')
    need(hashlib.sha256(read_root(DRIVER,131072)).hexdigest()==DRIVER_SHA,'Old driver differs')
    spec=importlib.util.spec_from_file_location('old_demo',DRIVER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    ns={'__name__':'transport'};exec(compile(read_root(Path('/var/lib/agentenv-root-relay/root-relay.py'),262144),'<transport>','exec'),ns);api=ns['api_module']()
    module_journal=json.loads(read_root(Path('/var/lib/agentenv-c-rootfs-maintenance-v1/module/journal.json')))
    ubse=module_journal['currentProcess']
    need(module_journal['phase']=='candidate_loaded_ubse_active' and m.ticks(ubse['pid'])==ubse['ticks']
         and m.unit('ubse.service')['MainPID']==str(ubse['pid']),'UBSE identity differs')
    if args.action=='restore':
        state=json.loads(read_root(REPAIR/'journal.json'))
        need(state.get('priorResourcesReleased') and (NEW/'journal.json').exists(),'Incomplete repair requires reconciliation; no implicit delete/group retry')
        m=configure_continuation(m,api,state,state['group']['gid']);sys.path.insert(0,str(NEW/'code'))
        current=json.loads(read_root(NEW/'journal.json'));need(not current['unknownCreate'],'Unconfirmed new creation must be reconciled first')
        plan_raw=(m.WORK/'rootfs-input-plan.json').read_bytes();need(hashlib.sha256(plan_raw).hexdigest()==m.PLAN_SHA,'Recovery input plan differs')
        demo=m.Demo(current,json.loads(plan_raw),api)
        try:
            for variant in ('original','dax'):
                if variant in current['units'] and not current['units'][variant].get('stopped'):demo.close_pair(variant)
            demo.release();api.atomic(NEW/'report.json',current)
            save(api,state,'owned_continuation_released_group_reserved')
        finally:publish(api,state)
        return
    state=json.loads(read_root(REPAIR/'journal.json'))
    prepared_raw=read_root(NEW/'journal.json');prepared=json.loads(prepared_raw)
    need(state.get('priorResourcesReleased') is True and state.get('device4DeleteAcknowledged') is True,
         'Old recovery not confirmed; do not repeat device deletion')
    need(prepared.get('reason')=='Unreviewed dependency config preserved'
         and prepared['unknownCreate'] is False and prepared['SDK_called'] is False
         and prepared['Guest_created'] is False and prepared['units']=={} and prepared['acl']==[]
         and prepared['guests']=={} and prepared['guestHistory']==[] and prepared['samples']==[],
         'Not a preparation-only failure; explicit reconciliation required')
    need(not (REPAIR/'resume-v12-before.json').exists(),'Resume intent already exists; no automatic retry')
    need(Path('/sys/module/obmm/refcnt').read_text().strip()=='0' and not list(Path('/dev').glob('obmm_shmdev*')),'Existing UB regions; preserve')
    gid=state['group']['gid'];group=grp.getgrnam(GROUP)
    need(group.gr_gid==gid and not group.gr_mem and prepared['reservedRuntimeGid']==gid,'Reserved group differs')
    need(not any(p.pw_gid==gid for p in pwd.getpwall()) and not process_rows(m,gid=gid),'Reserved group has users or processes')
    old_unit=m.unit(state['previousUnit']['name'])
    need(old_unit['MainPID']=='0' and old_unit['ActiveState']=='inactive','Old Runtime still active')
    need(not (m.WORK/'sdk-owner').exists() and not (NEW/'view').exists(),'SDK/view intent exists; do not allocate')
    response=json.loads(read_root(REPAIR/'device4-delete-response.json'))
    need(response['exitCode']==0 and json.loads(response['stdout'])=={'deviceId':4,'normalDeleteAcknowledged':True,'force':False},'Old normal delete acknowledgement differs')
    need(hashlib.sha256(read_root(NEW/'ublk-owner-query',65536)).hexdigest()=='0aaedab15e5171d40722dc3ac0b02f4378e7750b406c8b2dbeba4386b4e52b04','Query helper differs')
    for name in m.ublk_devices():
        if name.startswith('ublkc'):
            result=m.command([str(NEW/'ublk-owner-query'),name[5:]],2)
            need(result.returncode==0 and json.loads(result.stdout)['gid']!=gid,'Reserved group has a kernel device or query failed')
    m.write(REPAIR/'resume-v12-before.json',prepared_raw)
    state['resumeFromPreparationOnly']=True;save(api,state,'exact_file_reuse_resume_intent')
    try:
        m=configure_continuation(m,api,state,gid)
        plan_raw=(m.WORK/'rootfs-input-plan.json').read_bytes();need(hashlib.sha256(plan_raw).hexdigest()==m.PLAN_SHA,'T1 input plan differs')
        plan=json.loads(plan_raw)
        current=prepared
        current.pop('reason',None)
        demo=m.Demo(current,plan,api);demo.mark('prepared_resume_existing_inputs_verified')
        try:
            m.prepare_sources();demo.install_udev_rule()
            for name in ('/dev/obmm','/dev/ublk-control'):
                path=Path(name);s=path.stat();backup='acl-'+path.name+'.txt';m.write(NEW/backup,m.checked([m.tool('getfacl'),'-p',name]))
                current['acl'].append({'path':name,'rdev':s.st_rdev,'inode':s.st_ino,'backup':backup,'restored':False})
                demo.mark('device_acl_intent');m.checked([m.tool('setfacl'),'-m','u:1204:rw',name])
                current['acl'][-1]['appliedAclSha256']=hashlib.sha256(m.checked([m.tool('getfacl'),'-p',name])).hexdigest();demo.mark('device_acl_applied')
            demo.pair('original')
            for item in plan['files']:
                path=m.MIGRATED/'seed/repository/managed-layers'/(item['digest'].replace(':','_')+'.overlaybd.commit')
                need(m.digest(path)==item['digest'][7:],'Original lower changed; no UB publication')
            current['originalLowerIntegrityAfterExit']=True;demo.mark('original_lower_integrity_verified_before_candidate')
            demo.publish()
            current['brokerBeforeGuests']=demo.view('status');demo.pair('dax');current['brokerAfterGuests']=demo.view('status')
            need(current['brokerAfterGuests']['broker']['readBytes']>current['brokerBeforeGuests']['broker']['readBytes'],'No attributable DAX reads')
            need(len(current['guestProbes'])==4 and len({(x['path'],x['sha256']) for x in current['guestProbes']})==1,'Guest base content differs')
            demo.release()
            need(not process_rows(m,gid=gid),'Reserved group still has processes; do not declare release')
            for name in m.ublk_devices():
                if name.startswith('ublkc'):
                    result=m.command([str(NEW/'ublk-owner-query'),name[5:]],2)
                    need(result.returncode==0 and json.loads(result.stdout)['gid']!=gid,'Owned kernel device remains or query failed')
            current['functionalSmokePassed']=True;demo.mark('C_T1_DEDICATED_GROUP_TWO_GUESTS_PER_VARIANT_RELEASED')
        except BaseException as error:
            current['functionalSmokePassed']=False;current['reason']=str(error)
            if not current['unknownCreate']:
                try:
                    for variant in ('original','dax'):
                        if variant in current['units'] and not current['units'][variant].get('stopped'):demo.close_pair(variant)
                    demo.release()
                except BaseException as cleanup:current['cleanupError']=str(cleanup)
            demo.mark('stopped_preserve_resources');raise
        finally:
            try:
                if hasattr(demo,'permissions'):demo.permissions.stop()
            finally:api.atomic(NEW/'report.json',current)
        save(api,state,'functional_smoke_released_group_reserved_for_audit')
    except BaseException as error:
        state['reason']=str(error);state['errorType']=type(error).__name__;save(api,state,'stopped_preserve_repair_state');raise
    finally:publish(api,state)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps({'status':'C_T1_REPAIR_STOPPED_PRESERVE_STATE','reason':str(error)}));raise SystemExit(1)
