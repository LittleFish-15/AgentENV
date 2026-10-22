"""Account a measured, possibly nonzero post-drop baseline without hiding it."""
import base64, bisect, zlib


def need(ok,why):
    if not ok:raise RuntimeError(why)


def bitmaps(probe):
    result={}
    for row in probe['whole_lower_files']:
        expected=(row['file_bytes']+4095)//4096
        need(0<=expected<=32*1024**2,'Unexpected lower bitmap size')
        raw=base64.b64decode(row['residency_vector_zlib_base64'],validate=True)
        d=zlib.decompressobj();bits=d.decompress(raw,expected+1)
        need(d.eof and not d.unused_data and not d.unconsumed_tail and len(bits)==expected and all(v in (0,1) for v in bits),'Invalid complete residency bitmap')
        key=(row['dev'],row['inode']);need(key not in result,'Duplicate lower bitmap')
        need(sum(bits)*4096==row['resident_bytes'],'Bitmap/count differs')
        result[key]=bits
    need(sum(sum(b)*4096 for b in result.values())==probe['whole_lower_resident_bytes'],'Global bitmap total differs')
    return result


def range_index(ranges):
    return {k:([r[0] for r in spans],spans) for k,spans in ranges.items()}


def contains(index,page):
    dev,ino,n=page;starts,spans=index.get(str(dev)+':'+str(ino),([],[]))
    i=bisect.bisect_right(starts,n)-1
    return i>=0 and n<spans[i][0]+spans[i][1]


def enrich(frame,baseline_probe,template_keys):
    initial=bitmaps(baseline_probe);current=bitmaps(frame['residency_probe'])
    need(initial.keys()==current.keys(),'Baseline/current file scopes differ')
    baseline_total=0;still=set();by_key={}
    for key,bits in initial.items():
        now=current[key];need(len(bits)==len(now),'Lower page span changed')
        count=0
        for n,value in enumerate(bits):
            if value:
                count+=1
                if now[n]:still.add((key[0],key[1],n))
        baseline_total+=count;by_key[key]=count
    indices={sid:range_index(ranges) for sid,ranges in frame['accessed_page_ranges'].items()}
    global_common=set()
    for row in frame['templates']:
        keys=template_keys[row['template_id']];a,b=[indices[sid] for sid in row['sandbox_ids']]
        shared={page for page in still if page[:2] in keys and contains(a,page) and contains(b,page)}
        union={page for page in still if page[:2] in keys and (contains(a,page) or contains(b,page))}
        present=sum(page[:2] in keys for page in still);initial_count=sum(by_key[key] for key in keys)
        row.update(initial_lower_resident_bytes=initial_count*4096,
            initial_lower_pages_still_resident_bytes=present*4096,
            initial_lower_pages_no_longer_resident_bytes=(initial_count-present)*4096,
            lower_resident_outside_initial_page_set_bytes=row['whole_lower_host_pagecache_bytes']-present*4096,
            common_read_resident_from_initial_page_set_bytes=len(shared)*4096,
            common_read_resident_outside_initial_page_set_bytes=row['shared_accessed_host_pagecache_bytes']-len(shared)*4096,
            read_union_resident_from_initial_page_set_bytes=len(union)*4096)
        need(row['common_read_resident_outside_initial_page_set_bytes']>=0,'Baseline common pages exceed current common pages')
        global_common.update(shared)
    full=frame['residency_probe']['whole_lower_resident_bytes'];base_bytes=baseline_total*4096
    frame['baseline_page_accounting']={'initial_lower_resident_bytes':base_bytes,
        'initial_pages_still_resident_bytes':len(still)*4096,
        'initial_pages_no_longer_resident_bytes':base_bytes-len(still)*4096,
        'resident_outside_initial_page_set_bytes':full-len(still)*4096,
        'common_read_resident_from_initial_page_set_bytes':len(global_common)*4096,
        'common_read_resident_outside_initial_page_set_bytes':frame['global_same_template_shared_accessed_resident_bytes']-len(global_common)*4096,
        'net_lower_resident_change_bytes':full-base_bytes,
        'outside_initial_set_is_not_proof_of_trajectory_causation':True,
        'same_page_reloaded_cannot_be_distinguished_from_continuous_residency':True}


def reconcile(m,identity,api):
    old=m.B.read_json(m.ROOT/'relay/cow4-global-cache-node-a.pending.json')
    need(old['run_id']=='5a6b79e3138840f6849ed94be3a3b536' and old['status']=='STOPPED_COW4_ACCESS','Unexpected prior global attempt')
    need(old['reason']=='Global drop left target lower pages resident; no cold-replay claim; inspect checkpoint','Prior failure differs')
    jobs=old['jobs'];sids={j['sandbox_id'] for j in jobs}
    need(len(jobs)==len(sids)==8 and all(j['steps_completed']==0 for j in jobs) and old['replay_completed_guests']==0,'Prior replay was not empty')
    need(old['all_cohort_guests_released'] and not old['restore_outcome_uncertain'] and sids==set(old['released_sandboxes']),'Prior cleanup uncertain')
    root=old['root_session']
    need(root['status']=='COW4_ROOT_SESSION_RESTORED' and all(root.get(k) for k in
        ('original_configuration_restored','original_service_healthy','observer_exit_confirmed','bound_guest_processes_exited','other_services_unchanged')),'Prior restoration incomplete')
    need(tuple(root['restored_identity'])==tuple(identity),'Original service identity changed since confirmed restoration')
    need(len(root['global_pagecache_drops'])==1 and root['global_pagecache_drops'][0]['drop_write_completed'],'Prior drop history differs')
    need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original inventory not empty')
    for sid in sorted(sids):need(api.call('GET','/sandboxes/'+sid)[0]==404,'Previous Guest still exists')
    for pid,ticks in [old['observer_identity']]+[[b['pid'],b['start_ticks']] for b in old['bindings']]:
        try:alive=m.R.identity(pid)[1]==ticks
        except (FileNotFoundError,ProcessLookupError):alive=False
        need(not alive,'Previous measured process still alive')
    return {'previous_run_id':old['run_id'],'previous_report_directory':old['report_directory'],
        'prior_receipt_preserved':True,'previous_guests_http404':True,'prior_replay_actions':0,
        'change':'measured nonzero post-drop baseline with explicit page-set accounting; no all-zero cold claim'}
