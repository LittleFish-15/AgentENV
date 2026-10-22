"""Reconcile the completed IO64 experiment before an independent original run."""
import hashlib

ORIGINAL_SERVER_SHA='0c5478b8382289c05ab1730401eea6918420c35594604cc7131592e81ad5aeff'
IO64_RUN='e743a6785cfe48cbb822f8d87213f176'
FIRST_256_RUN='de320ed9ad9b4b8b9aa037ee9d4dcc8e'


def need(ok,why):
    if not ok:raise RuntimeError(why)


def reconcile(m,identity,api):
    old=m.B.read_json(m.ROOT/'relay/cow4-original-io64-node-a.pending.json')
    need(old['run_id']==IO64_RUN and old['status']=='COW4_IO64_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED','Expected completed IO64 trial')
    need(old['all_cohort_guests_released'] and not old['restore_outcome_uncertain'] and old['replay_completed_guests']==8,'Previous Guest lifecycle incomplete')
    previous=old['root_session']
    need(previous['status']=='COW4_ROOT_SESSION_RESTORED' and all(previous.get(k) for k in
         ('original_server_bytes_and_metadata_restored','original_configuration_restored','original_service_healthy','other_services_unchanged','observer_exit_confirmed','bound_guest_processes_exited','rootfs64_memory256_verified')),'Previous IO64 restore/effective limit evidence incomplete')
    need(tuple(previous['restored_identity'])==tuple(identity),'Original service changed since confirmed restoration')
    need(previous['original_server_sha256']==ORIGINAL_SERVER_SHA,'Previous original binary identity differs')
    need(len(old['jobs'])==8 and {j['sandbox_id'] for j in old['jobs']}==set(old['released_sandboxes']),'Previous Guest IDs differ')
    for j in old['jobs']:need(api.call('GET','/sandboxes/'+j['sandbox_id'])[0]==404,'Previous Guest remains')
    for pid,ticks in [old['observer_identity']]+[[b['pid'],b['start_ticks']] for b in old['bindings']]:
        try:alive=m.R.identity(pid)[1]==ticks
        except (FileNotFoundError,ProcessLookupError):alive=False
        need(not alive,'Previous experiment process remains')
    need(hashlib.sha256(m.H.read(m.BASE/'bin/server',256*1024**2)).hexdigest()==ORIGINAL_SERVER_SHA,'Installed binary is not the restored original')
    return {'previous_run_id':IO64_RUN,'first_256_run_id':FIRST_256_RUN,'previous_report_directory':old['report_directory'],
            'prior_receipts_preserved':True,'previous_guests_http404':True,'previous_processes_exited':True,
            'baseline_template_ids':sorted({j['template_id'] for j in old['jobs']}),
            'original_server_sha256':ORIGINAL_SERVER_SHA,
            'change':'Repeat original ae9c626 server and original c553 observer at actual 256 KiB; no IO64 candidate or source rebuild'}
