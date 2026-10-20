"""Read existing completed comparison metadata and calculate UB logical requests.

No SDK loading/calls, layer-content reads, service/config writes or allocations.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat

ROOT=Path('/home/jwk/agent')
REPO=ROOT/'deployments/agentenv-ub-b019f27/state/snapshot-store/repository'
ALIGN=4*1024**2
HEADER=4096

def need(ok,why):
    if not ok:raise RuntimeError(why)

def metadata(path):
    need(path.is_relative_to(ROOT) and path.resolve(strict=True)==path,'Redirected/outside input')
    m=path.lstat()
    need(stat.S_ISREG(m.st_mode) and m.st_uid==1204,'Unexpected file metadata')
    return m

def read(path):
    m=metadata(path);need(m.st_size<=1024**2,'Metadata input exceeds limit')
    with path.open('rb') as f:raw=f.read(1024**2+1)
    need(len(raw)==m.st_size,'Metadata changed during read')
    return raw

def main():
    need(socket.gethostname()=='server1' and os.getuid()==os.geteuid()==1204,'A ordinary jwk only')
    done=json.loads(read(ROOT/'relay/cow-modified-controlled-node-a.pending.json'))
    need(done.get('status')=='MODIFIED_UB_OFF_CONTROLLED_COMPLETED_REVIEW_COMPARABILITY'
         and done.get('marker_physical_expectations_matched') is True
         and done.get('restore_outcome_uncertain') is False and done.get('snapshot_outcome_uncertain') is False
         and len(done.get('known_sandboxes',[]))==4
         and set(done['known_sandboxes'])==set(done.get('released_sandboxes',[])),'Comparison/cleanup incomplete')
    prepared=json.loads(read(ROOT/'relay/cow-modified-prepare-node-a.json'))
    sid=done['snapshot_id']
    need(re.fullmatch(r'[0-9a-f-]{36}',sid) and prepared['snapshot_id']==sid,'Snapshot identity differs')
    raw=read(REPO/'catalog/records'/(sid+'.json'))
    need(hashlib.sha256(raw).hexdigest()==done['catalog_sha256']==prepared['catalog_sha256'],'Catalog changed')
    record=json.loads(raw)['committed'];rows={}
    for kind in ('memory','rootfs'):
        layers=record[kind+'_layers']
        need(len(layers)==(2 if kind=='memory' else 14),'Layer inventory differs')
        for item in layers:
            layer=item if kind=='memory' else item.get('Managed')
            need(isinstance(layer,dict),'Unresolved external layer')
            digest=layer.get('digest');size=layer.get('size')
            need(isinstance(digest,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',digest)
                 and type(size) is int and 0<size<=2*1024**3,'Invalid layer identity/size')
            rel='managed-layers/'+digest.replace(':','_')+'.overlaybd.commit'
            m=metadata(REPO/rel);receipt=prepared['files'][rel]
            need(m.st_size==size==receipt['bytes'] and receipt['sha256']==digest[7:],'Layer metadata/copy verification differs')
            if digest in rows:
                need(rows[digest]['stored_bytes']==size,'Duplicate digest with inconsistent size')
                rows[digest]['kinds'].append(kind);continue
            rows[digest]={'digest':digest,'kinds':[kind],'stored_bytes':size,'allocated_file_bytes':m.st_blocks*512,
                          'logical_mapping_bytes':((size+HEADER+ALIGN-1)//ALIGN)*ALIGN,
                          'path':str(REPO/rel),'device':m.st_dev,'inode':m.st_ino}
    values=list(rows.values())
    report={'status':'UB_LAYER_INVENTORY_ONLY_NO_SDK_CALLS','snapshot_id':sid,'layers':values,
            'unique_objects_planned':len(values),'payload_bytes_total':sum(x['stored_bytes'] for x in values),
            'logical_mapping_bytes_total':sum(x['logical_mapping_bytes'] for x in values),
            'largest_logical_mapping_bytes':max(x['logical_mapping_bytes'] for x in values),
            'mapping_formula':'ceil((stored_bytes + 4096) / 4194304) * 4194304',
            'formula_source':'tools/ub-snapshot/ub_layer_broker.py Publisher: HEADER_BYTES=4096, ALIGN=4MiB',
            'content_hashes_recomputed_this_run':False,'prior_copy_hashes_checked':True,
            'layer_contents_read':False,'SDK_called':False,'allocation_calls':0,'services_modified':False,
            'physical_allocation_bytes':None,'UB_pool_free_bytes':None,'platform_hard_quota_verified':False,
            'physical_note':'Logical mapping requests are not physical backing costs or enforced quotas; previous small-object coverage does not attest this batch.'}
    try:
        with Path('/sys/bus/ub/ub_feature').open() as f:line=f.readline(513).strip()
        need(len(line)<=512,'Feature line too long')
        report['ub_feature_first_line']=line
        report['share_noncache_advertised']=bool(int(line,0)&4)
    except Exception as e:
        report['ub_feature_error']={'type':type(e).__name__,'errno':getattr(e,'errno',None)}
    print('BEGIN_RETURN_REPORT');print(json.dumps(report,indent=2));print('END_RETURN_REPORT')

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_UB_INPUT_INVENTORY','type':type(e).__name__,
              'reason':str(e) if isinstance(e,RuntimeError) else 'Metadata read failed','SDK_called':False,'allocation_calls':0},indent=2))
        print('END_RETURN_REPORT');raise SystemExit(1)
