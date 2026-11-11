from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime
import csv,json,math,re,statistics
R=Path(__file__).resolve().parent/'results024';W=R/'analysis';W.mkdir(parents=True,exist_ok=True)
ops=[json.loads(s) for s in (R/'result/formal/operations.jsonl').read_text(encoding='utf-8').splitlines()]
summary=json.loads((R/'result/formal/summary.json').read_text());assert summary['valid'] and not summary['remaining_sandboxes']
selected={(o['sandbox_id'],o['phase']):o for o in ops if o['round']==1 and o['status']=='ok'};assert len(selected)==400
def duration(s):
 m=re.fullmatch(r'([\d.]+)(ns|µs|μs|us|ms|s)',s);assert m,s
 return float(m[1])*{'ns':1e-6,'µs':1e-3,'μs':1e-3,'us':1e-3,'ms':1,'s':1000}[m[2]]
def stat(v):
 v=sorted(v);return dict(n=len(v),mean=statistics.mean(v),p50=statistics.median(v),p95=v[math.ceil(len(v)*.95)-1],max=max(v)) if v else dict(n=0,mean=None,p50=None,p95=None,max=None)
roots={'create_sandbox':'create','pause_sandbox':'pause','resume_sandbox':'resume','delete_sandbox':'delete'}
events=defaultdict(list);counts=Counter();invalid=0;warm=Counter();root_missing=0
for line in (R/'trace/server-formal.jsonl').read_text(encoding='utf-8').splitlines():
 try:d=json.loads(line)
 except ValueError:invalid+=1;continue
 fields=d.get('fields') or {};span=d.get('span') or {};ctx=(d.get('spans') or [])+[span]
 root=next((s for s in ctx if s.get('name') in roots and s.get('sandbox_id')),None)
 if root is None:continue
 key=(root['sandbox_id'],roots[root['name']])
 if key not in selected:continue
 if fields.get('message')=='using warm firecracker from pool':warm[key[1]]+=1
 if fields.get('message')!='close' or 'time.busy' not in fields or 'time.idle' not in fields:continue
 stage=(d.get('target'),span.get('name'));busy=duration(fields['time.busy']);idle=duration(fields['time.idle'])
 events[key,stage].append(dict(ms=busy+idle,busy_ms=busy,idle_ms=idle,end=d['timestamp'],ancestor_spans=[s.get('name') for s in ctx[:-1]]));counts[key[1],*stage]+=1
print('INVALID_JSON',invalid,'WARM_HITS',dict(warm))
for phase in ['create','pause','resume','delete']:
 print('\n'+phase)
 for (p,t,n),v in counts.items():
  if p==phase:print(v,t,n)
def stage(t,n,label,parent):return (t,n,label,parent)
service='agentenv::orchestrator::service';sandbox='agentenv::sandbox::firecracker::sandbox';instance='agentenv::sandbox::firecracker::instance';envd='agentenv::sandbox::envd'
common=[stage(service,'launch_sandbox','launch_sandbox','operation span'),stage(sandbox,'start_resume','start_resume','launch_sandbox'),stage(instance,'load_snapshot_file','load_snapshot_file','start_resume'),stage(sandbox,'wait_for_ready','wait_for_ready','launch_sandbox'),stage(envd,'wait_for_ready','envd poll','wait_for_ready'),stage(envd,'init','envd init','wait_for_ready')]
stages={
 'create':[stage(service,'create_sandbox','create_sandbox','客户端总耗时')]+common,
 'resume':[stage(service,'resume_sandbox','resume_sandbox','客户端总耗时')]+common,
 'pause':[stage(service,'pause_sandbox','pause_sandbox','客户端总耗时'),stage(sandbox,'pause_to_dir','pause_to_dir','pause_sandbox'),stage(instance,'get_dirty_memory_ranges','get_dirty_memory_ranges','pause_to_dir'),stage(instance,'create_state_only_snapshot','create_state_only_snapshot','pause_to_dir'),stage(sandbox,'stop','stop_sandbox','pause_sandbox'),stage(instance,'stop','stop_instance','stop_sandbox')],
 'delete':[stage(service,'delete_sandbox','delete_sandbox','客户端总耗时'),stage(sandbox,'stop','stop_sandbox','delete_sandbox'),stage(instance,'stop','stop_instance','stop_sandbox')]
}
# Existing versions instrument some methods in sandbox instead of instance.
for phase,items in list(stages.items()):
 fixed=[]
 for t,n,label,parent in items:
  if counts[phase,t,n]==0:
   candidates=[target for (p,target,name),v in counts.items() if p==phase and name==n and v==100]
   if len(candidates)==1:t=candidates[0]
  fixed.append((t,n,label,parent))
 stages[phase]=fixed
rows=[];wide=[];coverage=[];aggregates=defaultdict(list)
for key,op in selected.items():
 phase=key[1];data={};out=dict(sandbox_id=key[0],operation=phase,round=1,client_ms=op['elapsed_sec']*1000)
 rows.append(dict(sandbox_id=key[0],operation=phase,stage='客户端总耗时',parent='',elapsed_ms=out['client_ms'],busy_ms=None,idle_ms=None,target='benchmark'))
 aggregates[phase,'客户端总耗时'].append(out['client_ms'])
 for t,n,label,parent in stages[phase]:
  found=events[key,(t,n)];coverage.append(dict(sandbox_id=key[0],operation=phase,stage=label,count=len(found)))
  if len(found)!=1:continue
  e=found[0];data[label]=e;out[label+'_ms']=e['ms']
  rows.append(dict(sandbox_id=key[0],operation=phase,stage=label,parent=parent,elapsed_ms=e['ms'],busy_ms=e['busy_ms'],idle_ms=e['idle_ms'],target=t));aggregates[phase,label].append(e['ms'])
 root=data.get(phase+'_sandbox')
 if root:
  def ts(s):return datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
  after=(ts(op['completed_at'])-ts(root['end']))*1000
  residuals={'客户端 span前（估算）':out['client_ms']-root['ms']-after,'客户端 span后':after,'客户端 span外合计':out['client_ms']-root['ms']}
  if phase in ['create','resume'] and len(data)==7:
   residuals.update({'start_resume其他':data['start_resume']['ms']-data['load_snapshot_file']['ms'],'wait_for_ready其他':data['wait_for_ready']['ms']-data['envd poll']['ms']-data['envd init']['ms'],'launch_sandbox其他':data['launch_sandbox']['ms']-data['start_resume']['ms']-data['wait_for_ready']['ms'],'operation span其他':root['ms']-data['launch_sandbox']['ms']})
  for name,v in residuals.items():
   out[name+'_ms']=v;rows.append(dict(sandbox_id=key[0],operation=phase,stage=name,parent='paired residual',elapsed_ms=v,busy_ms=None,idle_ms=None,target='paired difference'));aggregates[phase,name].append(v)
 wide.append(out)
issues=[r for r in coverage if r['count']!=1]
def write(name,data):
 with (W/name).open('w',encoding='utf-8-sig',newline='') as f:
  keys=list(dict.fromkeys(k for row in data for k in row))
  w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(data)
write('逐请求阶段明细.csv',rows);write('逐沙箱阶段宽表.csv',wide);write('阶段覆盖核验.csv',coverage)
stats={p:{n:stat(v) for (phase,n),v in aggregates.items() if phase==p} for p in stages}
result={'statistics':stats,'coverage_issues':issues,'invalid_json_lines':invalid,'formal_operations':len(selected),'warm_pool_hits':dict(warm),'span_counts':[{'phase':p,'target':t,'name':n,'count':v} for (p,t,n),v in counts.items()]}
(W/'stage-analysis.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
write('阶段统计.csv',[dict(operation=p,stage=n,**s) for p,a in stats.items() for n,s in a.items()])
for p in stages:
 values=sorted(o['elapsed_sec'] for o in selected.values() if o['phase']==p)
 for k,v in [('mean_sec',statistics.mean(values)),('p50_sec',statistics.median(values)),('p95_sec',values[94])]:assert math.isclose(summary[p][k],v,rel_tol=1e-8)
assert not invalid and not issues,{'invalid_json':invalid,'issues':issues[:20]}
print('\nCOVERAGE COMPLETE:',len(coverage),'spans matched; SDK metrics rechecked')
for p in stages:print(p,{n:round(s['mean'],3) for n,s in stats[p].items()})
