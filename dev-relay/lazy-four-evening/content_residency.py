"""Same-window content-range accounting. No physical-saving inference or target access."""
from collections import defaultdict
PAGE=4096

def need(ok,message):
    if not ok:raise ValueError(message)

def merge(ranges):
    result=[]
    for start,end in sorted(ranges):
        need(type(start) is int and type(end) is int and 0<=start<end,'Invalid half-open range')
        if result and start<=result[-1][1]:result[-1][1]=max(end,result[-1][1])
        else:result.append([start,end])
    return result

def intersect(a,b):
    a,b=merge(a),merge(b);i=j=0;out=[]
    while i<len(a) and j<len(b):
        lo=max(a[i][0],b[j][0]);hi=min(a[i][1],b[j][1])
        if lo<hi:out.append([lo,hi])
        if a[i][1]<b[j][1]:i+=1
        else:j+=1
    return out

def size(ranges):return sum(b-a for a,b in merge(ranges))

def shared_ranges(sets,threshold):
    events=defaultdict(int)
    for ranges in sets:
        for lo,hi in merge(ranges):events[lo]+=1;events[hi]-=1
    count=0;previous=None;out=[]
    for point,delta in sorted(events.items()):
        if previous is not None and count>=threshold and previous<point:out.append([previous,point])
        count+=delta;previous=point
    need(count==0,'Unbalanced ranges')
    return merge(out)

def observed_access(rows,bindings,cutoffs):
    """Bindings: source -> {guest, layers:{digest:fileBytes}}; one node per call.

    Input must already be an identity-checked observer trace prefix. This function
    validates attributed records but cannot prove missing records did not exist.
    """
    result={v['guest']:defaultdict(list) for v in bindings.values()}
    for row in rows:
        if row.get('kind')!='content_read':continue
        need(row.get('source') in bindings,'Unbound read source; coverage is unknown')
        binding=bindings[row['source']];guest=binding['guest'];key=row.get('digest')
        need(key in binding['layers'] and binding['layers'][key]==row.get('file_bytes'),'Content binding differs')
        need(row.get('allowed_lower') is True,'Read is outside the validated lower allowlist')
        need(row.get('from_ub') is True,'Repository fallback observed; do not classify as UB access')
        for field in ('start_ns','end_ns','offset','bytes'):need(type(row.get(field)) is int,'Missing exact read field')
        need(0<row['start_ns']<=row['end_ns'] and row['offset']>=0 and row['bytes']>0
             and row['offset']+row['bytes']<=row['file_bytes'],'Read range/time invalid')
        start,end=cutoffs[guest]
        # Cumulative completed reads within this workload's explicit observation interval.
        if row['start_ns']<start or row['end_ns']>end:continue
        lo=(row['offset']//PAGE)*PAGE
        hi=min(((row['offset']+row['bytes']+PAGE-1)//PAGE)*PAGE,row['file_bytes'])
        result[guest][key].append([lo,hi])
    return {guest:{key:merge(ranges) for key,ranges in by_key.items()} for guest,by_key in result.items()}

def ready_ranges(snapshot):
    need(snapshot.get('state')=='residency-snapshot' and snapshot.get('scope')=='logical-ready-content-not-physical-increment','Not a logical ready snapshot')
    out=defaultdict(list);seen=set();slots=set()
    for key,offset,length,slot in snapshot['ranges']:
        need((key,offset) not in seen and slot not in slots,'Duplicate or aliased cache slot')
        seen.add((key,offset));slots.add(slot);out[key].append([offset,offset+length])
    need(sum(size(r) for r in out.values())==snapshot['readyBytes'],'Ready content count differs')
    return {key:merge(ranges) for key,ranges in out.items()}

def summarize(access, resident, *, window_id, sets_validated):
    """Compute logical overlap at an explicitly coordinated observation window.

    Caller must validate identities and the observation window. This function
    computes only the supplied observed sets; it does not establish exhaustive IO.
    Whole lower residency cannot substitute for each Guest's access sets.
    """
    need(isinstance(window_id,str) and window_id and sets_validated is True,'Validated same-window sets required')
    need(2<=len(access)<=32,'Need 2..32 actual Guest access sets')
    selected={g:{k:intersect(v,resident.get(k,[])) for k,v in by_key.items()} for g,by_key in access.items()}
    keys=set().union(*(set(v) for v in selected.values()))
    union=shared=all_guests=0
    for key in keys:
        sets=[by_key.get(key,[]) for by_key in selected.values()]
        union+=size(shared_ranges(sets,1));shared+=size(shared_ranges(sets,2))
        all_guests+=size(shared_ranges(sets,len(selected)))
    participation=sum(size(r) for v in selected.values() for r in v.values())
    full=sum(size(r) for r in resident.values())
    need(0<=all_guests<=shared<=union<=full and participation>=union,'Set accounting invariant failed')
    return {'windowId':window_id,'scope':'logical-content-access-overlap-not-physical-net-saving',
            'fullReadyContentBytes':full,'accessedReadyUnionBytes':union,
            'sharedByAtLeastTwoGuestsBytes':shared,'allGuestIntersectionBytes':all_guests,
            'guestParticipationBytes':participation,'duplicateParticipationBytes':participation-union,
            'sharedOverAccessedRatio':shared/union if union else None,
            'sharedOverFullReadyRatio':shared/full if full else None,
            'perGuestAccessedReadyBytes':{g:sum(size(r) for r in v.values()) for g,v in selected.items()},
            'physicalNetSavingBytes':None,'guestFileCacheShared':None,'memfilePrivateCowShared':None,
            'fullAccessCoverageAccepted':False,'fullAccessedResidentUnionBytes':None,
            'fullSharedResidentBytes':None,'numericalValuesScope':'supplied observed prefix sets only'}
