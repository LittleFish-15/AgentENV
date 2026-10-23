"""Explicit repeat after the completed pair; preserve all previous receipts."""
def repeat_previous(m):
    expected={256:'8701803e0ccd4278bc71bef829c4c85a',64:'a2a2e2a1fb8d4344a6534975fdc5ce8b'}
    rows=[]
    for mode in (256,64):
        p=m.ROOT/('relay/cow4-memory-'+str(mode)+'-node-a.pending.json');r=m.B.read_json(p)
        m.need(r['run_id']==expected[mode] and r['all_cohort_guests_released'] and not r['restore_outcome_uncertain'],'Previous enhanced pair identity/release differs')
        required='COW4_ORIGINAL_256_RECHECK_MEASURED_GUESTS_RELEASED_RESTORED' if mode==256 else 'COW4_IO64_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED'
        m.need(r['status']==required and r['replay_completed_guests']==8,'Previous enhanced group incomplete')
        q=r['root_session']
        m.need(q['status']=='COW4_ROOT_SESSION_RESTORED' and all(q.get(k) for k in ('original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited')),'Prior root lifecycle incomplete')
        m.need(q.get('original_server_unchanged' if mode==256 else 'original_server_bytes_and_metadata_restored') is True,'Prior server restoration incomplete')
        m.need(r['memory_accounting']['coverage']['required_accounting_complete'],'Prior occupancy collection incomplete')
        rows.append(r)
    return rows


def reconcile_repeat(m,identity,api):
    m.need(MODE==256,'This repeat is original256 only');prior=repeat_previous(m)
    m.need(hashlib.sha256(m.H.read(m.BASE/'bin/server',256*1024**2)).hexdigest()=='0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff','Installed server is not original')
    m.need(api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Original inventory not empty')
    for r in prior:
        for j in r['jobs']:m.need(api.call('GET','/sandboxes/'+j['sandbox_id'])[0]==404,'Prior Guest remains')
        for pid,ticks in [r['observer_identity']]+[[b['pid'],b['start_ticks']] for b in r['bindings']]:
            try:alive=m.R.identity(pid)[1]==ticks
            except (FileNotFoundError,ProcessLookupError):alive=False
            m.need(not alive,'Prior experiment process remains')
    return {'reference_run_ids':[r['run_id'] for r in prior],'prior_receipts_preserved':True,
        'original_process_changed_since_prior':list(identity)!=prior[-1]['root_session']['restored_identity'],
        'baseline_template_ids':sorted({j['template_id'] for j in prior[-1]['jobs']}),
        'reason':'User reported possible concurrent compilation during the previous256 group; repeat original256 only.'}


BASE_MEMORY_ANNOUNCE=announce_memory_group


def announce_repeat(plan,cohort):
    prior=repeat_previous(ENGINE);fields=('template_id','parent_snapshot_id','catalog_sha256','slot','instance_id','replay_sha256','terminal_action')
    signature=lambda jobs:sorted(tuple(j[k] for k in fields) for j in jobs)
    for r in prior:
        for key in ('template_lowers','template_memory_lowers','boot_id'):
            ENGINE.need(plan[key]==r['root_plan'][key],'Repeat input changed: '+key)
        ENGINE.need(signature(cohort.jobs)==signature(r['jobs']),'Repeat templates/replays differ')
    cohort.report.update(reference_run_ids=[r['run_id'] for r in prior],repeat_input_equivalence_verified=True,
        prior256_possible_compilation_reported_by_user=True,prior256_compilation_causation_confirmed=False)
    BASE_MEMORY_ANNOUNCE(plan,cohort)


reconcile_memory=reconcile_repeat
announce_memory_group=announce_repeat
