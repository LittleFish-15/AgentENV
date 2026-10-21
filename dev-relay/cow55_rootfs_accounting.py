"""Account sampled file-cache objects and references, without node access.

Input is one sampling sweep, not concatenated historical samples. File identity
includes node and boot. File cache attribution is by reference, never causal IO
ownership or per-Guest accessed-offset overlap. Missing observations stay null.
"""
import json
from collections import defaultdict

FIELDS=('file_bytes','allocated_bytes','resident_bytes')
KINDS={'rootfs_lower','rootfs_upper','memory_lower'}

def total(files,ids,field):
    values=[files[i].get(field) for i in ids]
    return None if any(v is None for v in values) else sum(values)

def ratio(a,b):return a/b if a is not None and b is not None and b>0 else None

def analyze(sweep):
    files={};physical={}
    for f in sweep['files']:
        i=f['file_id'];key=tuple(f[k] for k in ('node','boot_id','device','inode'))
        if i in files or key in physical:raise ValueError('Duplicate sampled file identity; sample each inode once per sweep')
        if not all(type(f.get(k)) is int and f[k]>=0 for k in ('device','inode')):raise ValueError('Invalid inode identity')
        for name in FIELDS:
            v=f.get(name)
            if v is not None and (type(v) is not int or v<0):raise ValueError('Invalid observation')
        files[i]=f;physical[key]=i
    by_template=defaultdict(lambda:defaultdict(lambda:defaultdict(set)))
    memberships=defaultdict(set);upper_owners=defaultdict(set)
    for r in sweep['references']:
        i,t,s,k=r['file_id'],r['template_id'],r['sandbox_id'],r['kind']
        if i not in files or k not in KINDS:raise ValueError('Unresolved reference or kind')
        by_template[t][s][k].add(i);memberships[i].add(t)
        if k=='rootfs_upper':upper_owners[i].add((t,s))
    if any(len(v)>1 for v in upper_owners.values()):raise ValueError('Upper inode is shared by multiple sandboxes')
    rows=[]
    for template,sandboxes in sorted(by_template.items()):
        if len(sandboxes)!=2:raise ValueError('Exactly two identified sandboxes required per template')
        sids=sorted(sandboxes);a,b=[sandboxes[s] for s in sids]
        la,lb=a['rootfs_lower'],b['rootfs_lower'];common=la&lb;union=la|lb
        ua,ub=a['rootfs_upper'],b['rootfs_upper'];uppers=ua|ub
        if union&uppers:raise ValueError('File used both as rootfs lower and upper')
        if not la or not lb or not ua or not ub:raise ValueError('Incomplete rootfs reference inventory')
        other={i for i in union if len(memberships[i])>1}
        row={'template_id':template,'sandbox_ids':sids,'shared_lower_file_count':len(common),
             'cross_template_lower_file_count':len(other),'sandbox_metrics':[]}
        for sid,lower,upper in zip(sids,[la,lb],[ua,ub]):
            row['sandbox_metrics'].append({'sandbox_id':sid,
                **{'lower_'+k:total(files,lower,k) for k in FIELDS},
                **{'upper_'+k:total(files,upper,k) for k in FIELDS}})
        for prefix,ids in [('shared_lower',common),('unique_lower',union),('private_upper',uppers),
                           ('cross_template_lower',other),('lower_exclusive_to_this_template_in_observed_cohort',union-other)]:
            row.update({prefix+'_'+k:total(files,ids,k) for k in FIELDS})
        for field in ('allocated_bytes','resident_bytes'):
            unique=total(files,union|uppers,field);shared=total(files,common,field)
            row['shared_pool_fraction_'+field]=ratio(shared,unique)
            # Independent-copy model: duplicate every shared lower once, while
            # preserving current private uppers and non-common lower objects.
            counterfactual=None if unique is None or shared is None else unique+shared
            row['independent_copy_model_saving_fraction_'+field]=ratio(shared,counterfactual)
        row['per_guest_accessed_page_intersection_bytes']=None
        row['exclusive_host_cache_ownership_proven']=False
        rows.append(row)
    used=set(memberships)
    return {'status':'OBSERVED_FILE_REFERENCE_ACCOUNTING','sample_id':sweep['sample_id'],
            'template_count':len(rows),'templates':rows,
            'global_observed_unique_file_count':len(used),
            **{'global_observed_unique_'+k:total(files,used,k) for k in FIELDS},
            'total_host_pagecache_bytes':None,'net_UB_physical_savings_bytes':None,
            'sum_of_per_template_rows_is_global_total':False,
            'cache_attribution':'Referenced cache objects; not which Guest populated or accessed a page',
            'sample_atomic':False}

if __name__=='__main__':
    import argparse
    from pathlib import Path
    p=argparse.ArgumentParser();p.add_argument('input');p.add_argument('output');a=p.parse_args()
    raw=Path(a.input).read_bytes()
    if len(raw)>16*1024**2:raise ValueError('Input exceeds 16MiB')
    result=analyze(json.loads(raw))
    with Path(a.output).open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
