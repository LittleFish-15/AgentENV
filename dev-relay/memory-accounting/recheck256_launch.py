"""Restrict the executed paired packet to one fresh original256 observation."""
import ast,hashlib,json,os,stat,sys,types
from pathlib import Path
BASE_PACKET_SHA='95d3a5149425a562b85ad51befda18bc2ec2a6125a54c89e06566e9d918a1a8a'


def once(text,old,new):
    if text.count(old)!=1:raise RuntimeError('Pinned repeat anchor differs: '+old[:80])
    return text.replace(old,new)


def prepare(base,raw,owner_extension):
    original_payload=base.payload
    root=once(original_payload('root_pair'),'for mode in (256,64):','for mode in (256,):')
    root=root.replace('MEMORY_PAIR_ROOT_BOTH_GROUPS_RESTORED','MEMORY_256_RECHECK_ROOT_RESTORED')
    root=root.replace('memory-pair-root-v1','memory-original256-recheck-root-v1')
    owner=original_payload('owner_extension')+'\n'+owner_extension
    patches=original_payload('patch_sources')+'''
original_memory_stage_source=stage_source
def stage_source(raw,mode,extension):
    if mode!=256:raise RuntimeError('Only original256 stage permitted')
    text=original_memory_stage_source(raw,mode,extension)
    return once(text,"m.PENDING=m.ROOT/'relay/cow4-memory-256-node-a.pending.json'","m.PENDING=m.ROOT/'relay/cow4-memory-recheck-256-node-a.pending.json'")
'''
    base.payload=lambda name:{'root_pair':root,'owner_extension':owner,'patch_sources':patches}.get(name) or original_payload(name)
    main=ast.get_source_segment(raw,next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='main'))
    main=once(main,"for mode in (256,64):need(not (ROOT/f'relay/cow4-memory-{mode}-node-a.pending.json').exists()","for mode in (256,):need(not (ROOT/f'relay/cow4-memory-recheck-{mode}-node-a.pending.json').exists()")
    main=once(main,'for mode,(_,raw) in packets.items():compile','for mode,(_,raw) in [(256,packets[256])]:compile')
    main=once(main,"prefix='node-a-memory-pair-'","prefix='node-a-memory-recheck256-'")
    main=once(main,"'group_order':[256,64]","'group_order':[256]")
    main=once(main,"'maximum_restore_calls':16","'maximum_restore_calls':8")
    main=once(main,"'revision':'memory-pair-owner-v1'","'revision':'memory-original256-recheck-owner-v1'")
    main=once(main,'for mode in (256,64):\n            report', 'for mode in (256,):\n            report')
    main=once(main,'if mode==256:\n                print', 'if False:\n                print')
    main=once(main,"len(report['groups'])==2","len(report['groups'])==1")
    main=main.replace('MEMORY_PAIR_ROOT_BOTH_GROUPS_RESTORED','MEMORY_256_RECHECK_ROOT_RESTORED').replace('MEMORY_PAIR_BOTH_GROUPS_RELEASED_ACCOUNTING_COLLECTED','MEMORY_256_RECHECK_RELEASED_ACCOUNTING_COLLECTED')
    main=main.replace('COW4_MEMORY_PAIR_ROOT','COW4_MEMORY_256_RECHECK_ROOT')
    main=once(main,'Two groups run sequentially; four ordered host cache drops total; original service restored after each.','One original256 group; two ordered host cache drops total; original service restored afterward.')
    main=main.replace("work/'memory-comparison.json'","work/'memory-recheck256.json'").replace("work/'memory-comparison.md'","work/'memory-recheck256.md'")
    base.STATE=base.ROOT/'relay/cow4-memory-256-recheck-controller-node-a.pending.json'
    original_summary=base.pair_summary
    def summary(directory,groups):
        result=original_summary(directory,groups)
        result.update(revision='memory-original256-recheck-v1',group_order=[256],
            reference_runs={'previous256':'8701803e0ccd4278bc71bef829c4c85a','reference64':'a2a2e2a1fb8d4344a6534975fdc5ce8b'},
            previous256_possible_concurrent_compilation=True,compilation_causation_confirmed=False,
            reference_reports_preserved=True,measurement_logic_unchanged=True)
        base.dump(directory/'memory-recheck256.json',result)
        rows=['# 原版256 KiB增强内存采集复测','',
              '本次只重跑256；与已有64组a2a2e2a1对照。旧256组可能同时编译，尚未证明其残差全部由编译造成。',
              '四模板八Guest、既有程序、相同采集器；不重新编译、不重跑64。',
              'B1/T2 PFN覆盖单列；占用采集成功不等于全程物理共享证据完整。','']
        for g in result['groups']:
            rows.extend(['- run ID: '+g['run_id'],'- 生命周期状态: '+g['lifecycle_status'],'- 新采集覆盖: '+json.dumps(g.get('memory',{}).get('coverage',{}),ensure_ascii=False)])
        (directory/'memory-recheck256.md').write_text('\n'.join(rows)+'\n',encoding='utf-8')
        return result
    base.pair_summary=summary
    exec(compile(main,'original256-memory-repeat-main','exec'),base.__dict__)
    return base


def run():
    if sys.platform!='linux' or os.uname().nodename!='server1' or os.getuid()!=1204 or os.geteuid()!=1204:raise RuntimeError('A ordinary jwk only')
    path=Path('/home/jwk/agent/cow4_memory_pair_2bc47b8.py')
    if path.resolve(strict=True)!=path:raise RuntimeError('Redirected base packet')
    with path.open('rb') as f:
        meta=os.fstat(f.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=1204 or meta.st_size>1024**2:raise RuntimeError('Unexpected base packet metadata')
        raw=f.read(1024**2+1)
    if hashlib.sha256(raw).hexdigest()!=BASE_PACKET_SHA:raise RuntimeError('Executed paired packet hash differs')
    base=types.ModuleType('memory_repeat_base');base.__file__=str(path);sys.modules[base.__name__]=base;exec(compile(raw,str(path),'exec'),base.__dict__)
    return prepare(base,raw.decode(),REPEAT_OWNER).main()


if __name__=='__main__':
    try:raise SystemExit(run())
    except Exception as e:
        print('BEGIN_RETURN_REPORT');print(json.dumps({'status':'STOPPED_MEMORY_256_RECHECK_PRECONDITION','error_type':type(e).__name__,'reason':str(e)},indent=2));print('END_RETURN_REPORT');raise SystemExit(1)
