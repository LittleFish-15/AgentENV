"""Package the two-drop host-cache comparison; no workload or binary payload."""
import base64, hashlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
RELAY=HERE.parent


def once(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new)


def embedded(name,path):
    raw=path.read_bytes();data={'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()}
    return 'EMBEDDED['+repr(name)+']='+repr(data)+'\n'


def build():
    cold=(RELAY/'cow4_cold_once.py').read_text(encoding='utf-8')
    text,footer=cold.rsplit("if __name__=='__main__':",1)
    text=once(text,"parser.add_argument('mode',choices=('run','status'));args=parser.parse_args()",
        "parser.add_argument('mode',choices=('run','status'));parser.add_argument('--quiet-window-confirmed',action='store_true');parser.add_argument('--accept-nonzero-baseline',action='store_true');args=parser.parse_args()")
    text=once(text,"    if args.mode=='status':print(m.PENDING.read_text());return 0",
        "    if args.mode=='status':print(m.PENDING.read_text());return 0\n    m.need(args.quiet_window_confirmed,'Run requires --quiet-window-confirmed: global pagecache affects all A readers')\n    m.need(args.accept_nonzero_baseline,'Run requires --accept-nonzero-baseline: actual residual pages are measured, not claimed zero')")
    text=text.replace("m.PENDING=m.ROOT/'relay/cow4-cold-node-a.pending.json'","m.PENDING=m.ROOT/'relay/cow4-global-cache-v2-node-a.pending.json'")
    text=once(text,"    retry=None", "    retry=None\n    m.need(not (m.ROOT/'relay/cow4-cold-node-a.pending.json').exists(),'Scoped cold-run receipt exists; reconcile before global experiment')")
    text=text.replace("prefix='node-a-cow4-cold-'","prefix='node-a-cow4-global-'")
    text=once(text,"    identity=m.H.runtime_pid();api=m.Api(identity)","    identity=m.H.runtime_pid();api=m.Api(identity)\n    retry=BASELINE.reconcile(m,identity,api)")
    text=once(text,"'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'template_lowers':template_lowers}",
        "'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'template_lowers':template_lowers,\n        'operator_declared_quiet_window':args.quiet_window_confirmed,\n        'memory_lowers':[{k:f[k] for k in ('path','dev','inode','file_bytes')} for b in built for f in b['parent_layer_inventory']['memory']]}")
    text=once(text,"        COLD.enrich(frame,self.files,sets,resident)",
        "        COLD.enrich(frame,self.files,sets,resident)\n        if hasattr(self,'before_frame_write'):self.before_frame_write(frame)")
    text=once(text,"                cohort.report['cache_crosscheck_passed']=", """                drops=restored.get('global_pagecache_drops',[])
                cohort.report['two_global_drops_verified']=len(drops)==2 and [d.get('phase') for d in drops]==['idle_control','replay'] and all(d.get('sync_completed') and d.get('drop_write_completed') and d.get('value')==1 for d in drops)
                series=result.get('cache_timeseries',{})
                cohort.report['host_timeline_complete']=cohort.report.get('host_timeline',{}).get('error') is None and all(sum(r['phase']==phase for r in series.get('host_rows',[]))>=2 and sum(r['phase']==phase for r in series.get('file_rows',[]))>=2 for phase in ('idle_control','replay'))
                replay_processes=[r for r in result.get('process_rows',[]) if r['phase']=='both_replaying' and r['template_valid_paired_samples']>0]
                cohort.report['RSS_PSS_pair_coverage_complete']=len(replay_processes)==8 and len({r['template_id'] for r in replay_processes})==4
                cohort.report['cache_crosscheck_passed']=""")
    text=once(text,"and cohort.report['cache_crosscheck_passed']:",
        "and cohort.report['cache_crosscheck_passed'] and cohort.report['two_global_drops_verified'] and cohort.report['host_timeline_complete'] and cohort.report['RSS_PSS_pair_coverage_complete']:")
    text=text.replace('COW4_COLD_ACCESS_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','COW4_POST_DROP_BASELINE_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED')
    text=text.replace('COW4_COLD_ROOT','COW4_GLOBAL_V2_ROOT').replace("revision='cow4-cold-attributed-v1'","revision='cow4-global-cache-v2'")
    text=text.replace('仅对本批核验的 lower inode 做 DONTNEED，清理前后完整位图保留。',
        '本批由root在空载/回放前各清理一次整机pagecache，清理前后完整lower位图保留。')
    text=text.replace('每文件观测为零不代表全局原子冷态','初始残留按实际位图保留，不声明全零冷态')
    text=text.replace('冷缓存复核：','清理后基线复核：')
    text=text.replace('The root session restarts only the empty original service twice, samples scoped Guest metadata, then restores exact original configuration.',
        'The root session also performs exactly two host-wide sync + drop_caches=1 operations (before idle and replay), restarts only the empty original service twice, then restores exact original configuration.')
    addition=embedded('timeseries',HERE/'cache_timeseries.py')+embedded('global_root',HERE/'global_drop_root.py')+embedded('residual_baseline',HERE/'residual_baseline.py')
    addition += "TIMESERIES=_module('timeseries')\nBASELINE=_module('residual_baseline')\n"
    old="            elif op=='heartbeat':wire_send(sock,{'op':'heartbeat'})"
    new="            elif op=='drop_pagecache':\n                event=global_drop_once(request,report,plan,bound,others)\n                wire_send(sock,{'op':'drop_pagecache','event':event})\n"+old
    addition += 'assert ROOT_SOURCE.count('+repr(old)+')==1\n'
    addition += "ROOT_SOURCE=_source('global_root')+'\\n'+ROOT_SOURCE.replace("+repr(old)+','+repr(new)+')\n'
    addition += (HERE/'global_cache_run.py').read_text(encoding='utf-8')
    raw=(text+addition+"\nif __name__=='__main__':"+footer.replace('STOPPED_COW4_COLD_ENTRY','STOPPED_COW4_GLOBAL_ENTRY')).encode()
    compile(raw,'global-cache-packet','exec')
    (RELAY/'cow4_global_cache_once.py').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


if __name__=='__main__':print(build())
