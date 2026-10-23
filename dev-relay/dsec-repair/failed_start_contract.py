"""Evidence gates for this one failed launch, not a generic pending reset.

No I/O or API calls. A terminal failure plus GET 404 alone is not permission to
discard all lifecycle evidence. Activation additionally requires retirement of
the exact owning Runtime and proxy, verified by the root controller.
"""
import hashlib,json,re
RUN='2b3742a1258742bfa29de532b21bad08'
REQUEST='48865f2cd89d406fa1c02bf0c632279a'
SANDBOX='01a1682f-8d41-7e43-b636-5c1f6a62a3dc'
CONTEXT={'unit':'jwk-aenv-dsec-hostfile-v1-node-a.service','pid':1880294,'ticks':'52944913',
 'configSha256':'78de695ff5321938ccf614363bfa595badc68eefa75ab1f8908a5bb33876a600',
 'bootId':'58d0ee5f-f886-4eb6-93ea-a6328d14d139'}
MESSAGE=('sandbox '+SANDBOX+' operation Start failed: configure read-only native pmem layer: '
 'configure read-only native pmem layer: Request failed: 400 Bad Request - '
 '{"fault_message":"API Resource IDs can only contain alphanumeric characters and underscores."}')

def require(ok,message):
    if not ok:raise ValueError(message)

def check_failed_request(journal,error_log,cohort):
    require(journal.get('version')==1 and journal.get('runId')==RUN and
        journal.get('phase')=='needs_reconciliation' and journal.get('runtimeContext')==CONTEXT,
        'Different failed-run identity or Runtime context')
    require(journal.get('sandboxIds')==[] and journal.get('snapshots')==[] and
        journal.get('operations')==[] and journal.get('outcomeUncertain') is True,
        'Unexpected successful operations or known resources; use owned recovery first')
    pending=journal.get('openRequests')
    require(isinstance(pending,list) and len(pending)==1,'Expected exactly the original pending create')
    expected={'id':REQUEST,'kind':'create','route':'/sandboxes-cold','startedNs':1792749309194209960}
    require(pending[0]==expected,'Pending create changed; do not infer its outcome')
    require(cohort.get('version')==1 and cohort.get('dsecSmokeRunId')==RUN and
        cohort.get('phase')=='needs_reconciliation' and cohort.get('openRequests')==pending and
        cohort.get('sandboxIds')==[] and cohort.get('outcomeUncertain') is True,
        'Deployment lifecycle guard no longer describes this failed request')
    require(isinstance(error_log,bytes) and 0<len(error_log)<=32768,'Unexpected error-log size')
    rows=[json.loads(line) for line in error_log.decode().splitlines() if line.strip()]
    require(len(rows)==1,'Multiple HTTP failures; no implicit attribution')
    row=rows[0]
    require(row.get('method')=='POST' and row.get('path')=='/sandboxes-cold' and row.get('status')==500,
        'No exact terminal cold-create failure evidence')
    details=json.loads(row['details'])
    require(details.get('code')==500 and details.get('message')==MESSAGE,
        'Error is not the diagnosed pmem resource-ID rejection')
    return {'runId':RUN,'requestId':REQUEST,'failedSandboxId':SANDBOX,'runtimeContext':CONTEXT,
        'httpErrorSha256':hashlib.sha256(error_log).hexdigest(),'terminalHttpResponseObserved':True,
        'resourcesRetired':False,'pendingCanBeCleared':False}

def check_api_observation(status,body,inventory_status,inventory):
    require(inventory_status==200 and isinstance(inventory,list),'Inventory unavailable')
    if status==404:
        require(inventory==[],'Other Guest inventory exists; do not stop the service')
        return 'FAILED_ID_NOT_VISIBLE_REQUIRES_RUNTIME_RETIREMENT'
    require(status==200 and isinstance(body,dict) and body.get('sandboxID')==SANDBOX and
        body.get('metadata',{}).get('cow_batch')==RUN,'Sandbox ownership unconfirmed')
    require(all(isinstance(x,dict) and x.get('sandboxID')==SANDBOX and
        x.get('metadata',{}).get('cow_batch')==RUN for x in inventory) and len(inventory)==1,
        'Inventory contains an unrelated or ambiguous Guest')
    return 'KNOWN_OWNED_FAILED_GUEST_REQUIRES_EXPLICIT_DELETE'

def resolved_state(evidence,retirement):
    require(evidence.get('runId')==RUN and evidence.get('requestId')==REQUEST and
        evidence.get('failedSandboxId')==SANDBOX and evidence.get('runtimeContext')==CONTEXT and
        evidence.get('terminalHttpResponseObserved') is True and
        re.fullmatch('[0-9a-f]{64}',evidence.get('httpErrorSha256','')) is not None,
        'Failure evidence changed')
    require(retirement.get('runtimeContext')==CONTEXT and
        all(retirement.get(key) is True for key in ('apiInventoryEmpty','failedIdGet404',
          'oldMainProcessExitConfirmed','oldRuntimeCgroupEmpty','oldHostProxyExitConfirmed',
          'oldProviderStopped','olderServicesUnchanged')),
        'Scoped retirement is incomplete; preserve original pending')
    require(retirement.get('requestId')==REQUEST and retirement.get('runId')==RUN,
        'Retirement refers to a different run')
    return {'version':1,'phase':'prepared','sandboxIds':[],'openRequests':[],
        'outcomeUncertain':False,'retiredFailedStart':{'runId':RUN,'requestId':REQUEST,
         'failedSandboxId':SANDBOX,'httpErrorSha256':evidence['httpErrorSha256'],
         'basis':'EXACT_HTTP_FAILURE_AND_API_ABSENCE_AND_OWNING_RUNTIME_RETIRED',
         'originalJournalPreserved':True}}
