"""Summarize synchronized pair observations; never infer memfile PFN sharing.

Each input JSONL line represents one template pair within one collector sweep.
Sampler-produced identity checks and separate timing remain part of evidence.
This reducer does not access nodes, collect processes, or create sandboxes.
"""
from collections import Counter
import json
import math

KEYS=('run_id','variant','mode','node','boot_id','phase','template_id')

def extent(values):
    return {'min':min(values),'max':max(values)} if values else {'min':None,'max':None}

class Summary:
    def __init__(self):self.groups={}
    def add(self,frame):
        key=tuple(frame[k] for k in KEYS)
        if any(not isinstance(k,str) or not k for k in key):raise ValueError('Missing group identity')
        sids=frame['sandbox_ids']
        if len(sids)!=2 or len(set(sids))!=2 or any(not isinstance(s,str) or not s for s in sids):raise ValueError('Exactly two fixed sandbox IDs required')
        start,end=frame['started_unix'],frame['finished_unix']
        if any(type(t) not in (int,float) or not math.isfinite(t) for t in (start,end)) or end<start:raise ValueError('Invalid sample times')
        group=self.groups.setdefault(key,{'ids':tuple(sids),'seen':set(),'start':[],'end':[],
            'samples':{s:{'rss':[],'pss':[],'difference':[],'invalid':Counter()} for s in sids},'shared':[]})
        if group['ids']!=tuple(sids):raise ValueError('Pair identity changed within group')
        sample_id=frame['sample_id']
        if not isinstance(sample_id,str) or not sample_id or sample_id in group['seen']:raise ValueError('Missing/duplicate sample ID')
        group['seen'].add(sample_id);group['start'].append(start);group['end'].append(end)
        processes={}
        for p in frame['processes']:
            sid=p['sandbox_id']
            if sid not in sids or sid in processes:raise ValueError('Unexpected/duplicate process')
            processes[sid]=p
        differences=[]
        for sid in sids:
            p=processes.get(sid,{})
            rss,pss=p.get('rss_bytes'),p.get('pss_bytes')
            reason=None
            if not p:reason='missing_process'
            elif p.get('identity_verified') is not True:reason='identity_unverified'
            elif any(type(v) is not int or v<0 for v in (rss,pss)):reason='missing_or_invalid_RSS_PSS'
            elif rss<pss:reason='non_atomic_RSS_below_PSS'
            if reason:group['samples'][sid]['invalid'][reason]+=1;continue
            item=group['samples'][sid];item['rss'].append(rss);item['pss'].append(pss);item['difference'].append(rss-pss)
            differences.append(rss-pss)
        if len(differences)==2:group['shared'].append(sum(differences)) # n - 1 = 1
    def result(self):
        rows=[]
        for key,g in sorted(self.groups.items()):
            shared=extent(g['shared']);attempts=len(g['seen']);starts=sorted(g['start'])
            intervals=[b-a for a,b in zip(starts,starts[1:])]
            for sid in g['ids']:
                data=g['samples'][sid]
                row=dict(zip(KEYS,key),sandbox_id=sid,
                    sandbox_valid_samples=len(data['rss']),template_valid_paired_samples=len(g['shared']),
                    attempted_samples=attempts,template_invalid_paired_samples=attempts-len(g['shared']),
                    template_min_shared_bytes=shared['min'],template_max_shared_bytes=shared['max'],
                    window_start_unix=min(g['start']),window_end_unix=max(g['end']),
                    actual_interval_min_seconds=min(intervals) if intervals else None,
                    actual_interval_max_seconds=max(intervals) if intervals else None,
                    reached_reference_1200_paired_samples=len(g['shared'])>=1200,
                    invalid_reasons=dict(data['invalid']),
                    shared_scope='whole_Firecracker_equivalent_not_memfile_PFN',
                    template_sharing_method='per_sample_sum_RSS_minus_PSS_div_n_minus_1_n_equals_2')
                for name,metric in [('rss','rss'),('pss','pss'),('rss_minus_pss','difference')]:
                    values=extent(data[metric]);row['sandbox_min_'+name+'_bytes']=values['min'];row['sandbox_max_'+name+'_bytes']=values['max']
                rows.append(row)
        return {'status':'SUMMARY_OF_PROVIDED_PROCESS_OBSERVATIONS','rows':rows,
                'sample_padding_performed':False,'memfile_physical_shared_bytes_inferred':False,
                'all_55_experiments_complete_inferred':False}

if __name__=='__main__':
    import argparse
    from pathlib import Path
    p=argparse.ArgumentParser();p.add_argument('samples');p.add_argument('output');a=p.parse_args()
    summary=Summary()
    with Path(a.samples).open(encoding='utf-8') as f:
        for line in f:
            if len(line)>1024**2:raise ValueError('Frame exceeds 1MiB')
            if line.strip():summary.add(json.loads(line))
    with Path(a.output).open('x',encoding='utf-8') as f:json.dump(summary.result(),f,ensure_ascii=False,indent=2)
