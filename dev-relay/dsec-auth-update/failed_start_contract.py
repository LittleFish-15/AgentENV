"""Evidence gates for this one failed launch, not a generic pending reset.

No I/O or API calls. A terminal failure plus GET 404 alone is not permission to
discard all lifecycle evidence. Activation additionally requires retirement of
the exact owning Runtime and proxy, verified by the root controller.
"""
import hashlib,json,re
RUN = '882218af00354a25b5fcb1aeb2f6e4a0'
REQUEST = '2dcf2eb01d3a4285b596bcf019b37037'
SANDBOX = '01a16bae-31e4-7123-9264-1df2798ceb57'
CONTEXT = {'unit': 'jwk-aenv-dsec-hostfile-v1-node-a.service', 'pid': 2385984, 'ticks': '58987587', 'configSha256': '78de695ff5321938ccf614363bfa595badc68eefa75ab1f8908a5bb33876a600', 'bootId': '58d0ee5f-f886-4eb6-93ea-a6328d14d139'}
MESSAGE = 'sandbox 01a16bae-31e4-7123-9264-1df2798ceb57 operation WaitReady failed: gRPC stream error while waiting for start event: gRPC stream error while waiting for start event: code: \'Internal error\', message: "protocol error: received message with invalid compression flag: 123 (valid flags are 0 and 1) while receiving response with status: 401 Unauthorized"'

def require(ok,message):
    if not ok:raise ValueError(message)

def check_failed_request(journal,error_log,cohort):
    require(journal.get('version')==1 and journal.get('runId')==RUN and
        journal.get('phase')=='needs_reconciliation' and journal.get('runtimeContext')==CONTEXT,
        'Different failed restore identity or Runtime context')
    require(journal.get('sandboxIds')==[] and journal.get('snapshots')==[SNAPSHOT] and
        journal.get('outcomeUncertain') is True,'Unexpected restore resource inventory')
    operations=journal.get('operations',[])
    require(len(operations)==3 and [o.get('kind') for o in operations]==['create','capture','delete'] and
        [o.get('httpStatus') for o in operations]==[201,201,204] and
        operations[0].get('ack',{}).get('sandboxIds')==[PARENT] and
        operations[1].get('ack',{}).get('snapshotId')==SNAPSHOT and
        operations[2].get('route')=='/sandboxes/'+PARENT,'Successful cold/capture/parent retirement differs')
    snapshots=journal.get('snapshotEvidence',[])
    require(len(snapshots)==1 and snapshots[0].get('snapshotId')==SNAPSHOT and
        snapshots[0].get('committedRecordSha256')==SNAPSHOT_SHA,'Retained capture identity differs')
    pending=journal.get('openRequests')
    require(isinstance(pending,list) and len(pending)==1 and
        pending[0].get('id')==REQUEST and pending[0].get('kind')=='create' and
        pending[0].get('route')=='/v2/sandboxes' and not pending[0].get('ack'),
        'Expected only the observed unacknowledged restore')
    require(cohort.get('version')==1 and cohort.get('dsecSmokeRunId')==RUN and
        cohort.get('phase')=='needs_reconciliation' and cohort.get('openRequests')==pending and
        cohort.get('sandboxIds')==[] and cohort.get('outcomeUncertain') is True,
        'Deployment guard differs from failed restore')
    require(isinstance(error_log,bytes) and 0<len(error_log)<=32768,'Unexpected error-log size')
    rows=[json.loads(line) for line in error_log.decode().splitlines() if line.strip()]
    require(len(rows)==1 and rows[0].get('method')=='POST' and rows[0].get('path')=='/v2/sandboxes'
        and rows[0].get('status')==500,'No unique terminal restore failure')
    details=json.loads(rows[0]['details'])
    require(details.get('code')==500 and details.get('message')==MESSAGE,'Different restore failure')
    return {'runId':RUN,'requestId':REQUEST,'failedSandboxId':SANDBOX,'runtimeContext':CONTEXT,
        'httpErrorSha256':hashlib.sha256(error_log).hexdigest(),'terminalHttpResponseObserved':True,
        'resourcesRetired':False,'pendingCanBeCleared':False,'retainedSnapshotId':SNAPSHOT,
        'retainedSnapshotRecordSha256':SNAPSHOT_SHA}

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

SNAPSHOT='01a16bae-2f76-77b3-b7a7-a34bf65a25dc'
SNAPSHOT_SHA='c799bfab8e95757a0e5d11c1168fb2f52cba10f49d49bd32980e5239a4c2634e'
PARENT='01a16bae-1349-77f2-afe0-20f9b064ce10'
