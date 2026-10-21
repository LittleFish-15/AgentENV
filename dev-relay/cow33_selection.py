"""Deterministic representative selection from the existing private 55-case input."""
import base64, hashlib, json, re
QUOTAS={'go':18,'ts':9,'java':6}
PATTERNS={
    'go_test':r'\bgo\s+test\b','go_build':r'\bgo\s+build\b','go_vet':r'\bgo\s+vet\b',
    'go_format':r'\b(?:gofmt|go\s+fmt)\b','js_package_manager':r'\b(?:npm|yarn|pnpm|npx)\b',
    'js_test':r'\b(?:jest|vitest|mocha|npm\s+(?:run\s+)?test|yarn\s+test|pnpm\s+test)\b',
    'maven':r'\b(?:mvn|mvnw)\b','gradle':r'\b(?:gradle|gradlew)\b',
    'python_command':r'\b(?:python3?|pytest)\b','shell_text_edit':r'\b(?:sed|perl|str_replace_editor|apply_patch)\b',
    'git_inspection':r'\bgit\s+(?:diff|status|show|log)\b',
    'file_search_read':r'\b(?:grep|rg|find|cat|head|tail)\b',
    'dependency_command':r'\b(?:npm\s+(?:install|ci)|yarn\s+install|pnpm\s+install|go\s+mod|pip3?\s+install)\b',
}
def features(case,inputs):
    raw=base64.b64decode(inputs['replays'][case['replay_file']],validate=True)
    if hashlib.sha256(raw).hexdigest()!=case['replay_sha256']:raise ValueError('Replay digest differs')
    data=json.loads(raw);actions=[]
    for item in data['trajectory']:
        action=item.get('action','') if isinstance(item,dict) else ''
        if not isinstance(action,str):continue
        if action.strip().lower() in ('submit','finish','done'):break
        actions.append(action)
    text='\n'.join(actions);wall=case['reference_wall_seconds']
    bucket='short' if wall<600 else 'medium' if wall<1200 else 'long'
    return {'language:'+case['language'],'duration:'+case['language']+':'+bucket}|{name for name,p in PATTERNS.items() if re.search(p,text)}
def select(inputs):
    cases=inputs['cohort']['cases']
    if len(cases)!=55 or len({c['instance_id'] for c in cases})!=55:raise ValueError('Expected existing unique 55 cases')
    fs=[features(c,inputs) for c in cases];all_features=set().union(*fs);selected=[]
    repo=lambda i:cases[i]['instance_id'].rsplit('-',1)[0]
    for lang in QUOTAS:
        indexes=[i for i,c in enumerate(cases) if c['language']==lang]
        ordered=sorted(indexes,key=lambda i:(cases[i]['reference_wall_seconds'],cases[i]['instance_id']))
        selected.extend([ordered[0],ordered[-1]])
    while len(selected)<33:
        seen=set().union(*(fs[i] for i in selected));repos={repo(i) for i in selected}
        counts={l:sum(cases[i]['language']==l for i in selected) for l in QUOTAS}
        eligible=[i for i,c in enumerate(cases) if i not in selected and counts[c['language']]<QUOTAS[c['language']]]
        def score(i):
            novelty=sum(100/sum(f in row for row in fs) for f in fs[i]-seen)
            distance=min(abs(cases[i]['reference_wall_seconds']-cases[j]['reference_wall_seconds']) for j in selected if cases[j]['language']==cases[i]['language'])
            return (novelty,repo(i) not in repos,distance,cases[i]['instance_id'])
        selected.append(max(eligible,key=score))
    covered=set().union(*(fs[i] for i in selected))
    if covered!=all_features:raise ValueError('Not all declared observable feature categories covered')
    batches=[[],[]];caps=[{'go':9,'ts':5,'java':3},{'go':9,'ts':4,'java':3}]
    for lang in QUOTAS:
        for i in sorted((i for i in selected if cases[i]['language']==lang),key=lambda i:(-cases[i]['recorded_wait_seconds'],cases[i]['instance_id'])):
            eligible=[b for b in range(2) if sum(cases[j]['language']==lang for j in batches[b])<caps[b][lang]]
            b=min(eligible,key=lambda b:(sum(cases[j]['recorded_wait_seconds'] for j in batches[b]),len(batches[b]),b));batches[b].append(i)
    result={'revision':'cow33-selection-v1','quotas':QUOTAS,'batch_sizes':[len(b) for b in batches],
        'batch_indexes':[sorted(b) for b in batches],'covered_features':sorted(covered),
        'coverage_interpretation':'Language, reference-duration buckets, and lexical command families; not every project or every scenario in the original 55.',
        'batch_comparability':'Two sequential independent concurrency groups; do not add cross-batch caches or claim 66 simultaneous Guests.',
        'selected':[{**cases[i],'source_index':i,'batch':next(b+1 for b in range(2) if i in batches[b]),'observed_features':sorted(fs[i])} for i in sorted(selected)]}
    result['selection_sha256']=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result
