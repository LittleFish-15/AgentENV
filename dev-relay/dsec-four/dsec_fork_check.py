"""One bounded two-child Fork request with durable partial-response evidence."""
import copy, re, time, uuid


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def response_ids(status, reply):
    if status != 201 or not isinstance(reply, list) or len(reply) != 2:
        return [], False
    found, complete = [], True
    for entry in reply:
        if not isinstance(entry, dict):
            complete = False;continue
        sandbox = entry.get('sandbox')
        sid = sandbox.get('sandboxID') if isinstance(sandbox, dict) else None
        if isinstance(sid, str) and re.fullmatch('[A-Za-z0-9_-]{1,128}', sid):
            if sid not in found:
                found.append(sid)
            else:
                complete = False
        else:
            complete = False
        if entry.get('error') is not None:
            complete = False
    return found, complete and len(found) == 2


def register_acknowledged(case, request):
    ids = request.get('forkPairAckIds', [])
    need(isinstance(ids, list) and len(ids) == len(set(ids)) <= 2 and
         all(isinstance(sid, str) and re.fullmatch('[A-Za-z0-9_-]{1,128}', sid) for sid in ids),
         'Invalid Fork pair acknowledgment identities')
    need(request.get('sourceId') not in ids, 'Fork response aliases source identity')
    combined = list(dict.fromkeys(case.state['sandboxIds'] + ids))
    need(len(combined) <= 3, 'Fork recovery exceeds owned Guest bound')
    case.state['sandboxIds'] = combined
    case.save()
    for sid in ids:
        # owned() enforces the exact cow_batch before any destructive operation.
        case.owned(sid)
    return ids


def reconcile_pair(case):
    for request in list(case.state['openRequests']):
        if request.get('kind') != 'fork_pair':
            continue
        need(request.get('route') == '/sandboxes/' + request.get('sourceId', '') + '/fork'
             and request.get('expectedCount') == 2, 'Fork pair intent changed')
        if 'forkPairAckIds' not in request:
            continue
        ids = register_acknowledged(case, request)
        if request.get('forkPairCompleteResponse') is True and request.get('responseHttpStatus') == 201 and len(ids) == 2:
            case.state['openRequests'].remove(request)
            case.state['operations'].append({**request, 'reconciledBy': 'DURABLE_TWO_CHILD_RESPONSE',
                                            'finishedNs': time.time_ns()})
            case.save()
        # A partial response does not prove the other child has no residual
        # resources. Known IDs can be cleaned; uncertainty remains in the intent.


def fork_pair(case, source):
    if case.mutation_guard is not None:
        case.mutation_guard()
    need(case.state['sandboxIds'] == [source] and not case.state['openRequests'],
         'Fork pair requires exactly one owned source and no uncertain requests')
    need(case.owned(source) is not None, 'Fork source absent')
    case.capacity('fork_pair')
    request = {'id': uuid.uuid4().hex, 'kind': 'fork_pair', 'sourceId': source,
               'route': '/sandboxes/' + source + '/fork', 'expectedCount': 2, 'startedNs': time.time_ns()}
    case.state['openRequests'].append(request)
    case.save()
    began = time.monotonic()
    status, reply = case.api.call('POST', request['route'], {'count': 2, 'timeout': 1800}, timeout=600)
    ids, complete = response_ids(status, reply)
    request.update(responseHttpStatus=status, forkPairAckIds=ids, forkPairCompleteResponse=complete)
    case.save()  # Register the complete bounded acknowledgment before GETs.
    registered = register_acknowledged(case, request)
    need(complete and len(registered) == 2, 'Fork pair incomplete; preserve intent and known children')
    need(all(case.owned(sid) is not None for sid in registered), 'Fork child vanished before verification')
    case.state['openRequests'].remove(request)
    case.state['operations'].append({**request, 'httpStatus': status, 'seconds': time.monotonic()-began,
                                    'finishedNs': time.time_ns()})
    case.save()
    return registered


def extend_engine(engine):
    if getattr(engine, '_dsec_fork_pair_extension', False):
        return engine
    original = engine.Cohort
    class ForkCohort(original):
        def recover_owned(self):
            try:
                reconcile_pair(self)
            except Exception as error:
                self.state.setdefault('reconciliationErrors', []).append({'kind': 'fork_pair', 'errorType': type(error).__name__})
                self.save()
            return super().recover_owned()
    engine.Cohort = ForkCohort
    engine._dsec_fork_pair_extension = True
    return engine


def exercise(case, template, execute):
    source = case.create('/v2/sandboxes', {'templateID': template['nativeTemplateId'], 'timeout': 1800,
        'secure': True, 'autoPause': False, 'allow_internet_access': False,
        'metadata': {'cow_batch': case.run_id, 'dsec_fork_check': 'source'}})
    execute(source, 'source-prepare', 'parent')
    children = fork_pair(case, source)
    execute(source, 'source-resumed', 'check')
    case.delete(source)
    for index, sid in enumerate(children):
        execute(sid, 'after-source-exit-' + str(index), 'check')
    execute(children[0], 'writer-copy-up', 'write')
    execute(children[1], 'peer-original', 'check')
    execute(children[0], 'writer-private', 'private')
    case.delete(children[0])
    execute(children[1], 'after-writer-exit', 'check')
    return {'children': children, 'sourceId': source, 'sourceResumedAfterFork': True,
            'childrenReadableAfterSourceExit': True, 'survivorReadableAfterSiblingExit': True,
            'privateCopyUpIsolationPassed': True, 'singleForkRequestCount': 2,
            'concurrentChildStartupRequested': True, 'newCatalogSnapshotsCreated': 0,
            'retainedCleanParentModified': False, 'newGuestInstances': 3,
            'scope': 'single-node pmem lifecycle, not UB or physical savings acceptance'}
