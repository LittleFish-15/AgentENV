"""Bounded API lifecycle with write-ahead request evidence and owned cleanup.

No remote effects on import. The caller holds the deployment/cohort lock for
the complete run. Unknown POST outcomes remain pending even when inventory is
currently empty: a timed-out request can still complete on the server.
"""
import copy
import re
import time
import uuid


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value),
            'Missing or invalid API identity')
    return value


def quiescent(state):
    return (state.get('version') == 1 and state.get('phase') in ('prepared', 'quiesced')
            and state.get('sandboxIds') == [] and state.get('openRequests') == []
            and state.get('outcomeUncertain') is False)


def acknowledged_identity(kind, status, reply):
    """Persist only bounded identities, never API tokens or opaque responses."""
    try:
        if kind == 'create' and status == 201 and isinstance(reply, dict):
            return {'sandboxIds': [identifier(reply.get('sandboxID'))]}
        if kind == 'fork' and status == 201 and isinstance(reply, list) and len(reply) == 1:
            row = reply[0]
            if isinstance(row, dict) and row.get('error') is None and isinstance(row.get('sandbox'), dict):
                return {'sandboxIds': [identifier(row['sandbox'].get('sandboxID'))]}
        if kind == 'capture' and status in (200, 201) and isinstance(reply, dict):
            return {'snapshotId': identifier(reply.get('snapshotID'))}
    except RuntimeError:
        pass
    return None


def release_captures(api, state, persist, record):
    """Explicitly remove only this journal's captured IDs through the API.

    `record(id)` returns the current committed record's SHA or None when absent.
    A prior uncertain DELETE is only checked for absence, never reissued.
    Unknown creates/captures/Forks always block this operation.
    """
    require(state.get('version') == 1 and not state.get('sandboxIds'), 'Owned Guests must be released first')
    snapshots = state.get('snapshots')
    requests = state.get('openRequests')
    require(isinstance(snapshots, list) and len(snapshots) <= 1 and isinstance(requests, list)
            and all(r.get('kind') == 'delete_capture' and r.get('snapshotId') in snapshots for r in requests),
            'Unresolved non-release requests block capture deletion')
    evidence = state.get('snapshotEvidence', [])
    def save():
        state['outcomeUncertain'] = bool(state['openRequests'])
        persist(state)
    def empty():
        require(api.call('GET', '/v2/sandboxes?limit=1') == (200, []), 'Running/paused inventory must be empty')
    try:
        empty()
        for sid in list(snapshots):
            require(str(uuid.UUID(sid)) == sid, 'Capture deletion requires a literal canonical UUID, never an alias')
            rows = [e for e in evidence if e.get('snapshotId') == sid]
            require(len(rows) == 1 and re.fullmatch('[0-9a-f]{64}', rows[0].get('committedRecordSha256', '')),
                    'Original committed capture hash missing; retain the snapshot')
            expected = rows[0]['committedRecordSha256']
            route = '/templates/' + sid
            prior = [r for r in requests if r.get('snapshotId') == sid]
            require(len(prior) <= 1 and all(r.get('route') == route and r.get('recordSha256') == expected for r in prior),
                    'Pending capture release differs from the captured record')
            current = record(sid)
            if current is not None:
                require(current == expected, 'Committed capture changed; no deletion requested')
            if prior:
                require(current is None and api.call('GET', route)[0] == 404,
                        'Previous capture DELETE is unconfirmed; no second DELETE requested')
                request = prior[0]
                method = 'RECONCILED_GET_404_AND_RECORD_ABSENT'
            elif current is None:
                require(api.call('GET', route)[0] == 404, 'Missing local record disagrees with API')
                request = None
                method = 'ALREADY_ABSENT_CONFIRMED'
            else:
                # Recheck both the empty service and the pinned record directly
                # before recording the single mutation intent.
                empty()
                require(record(sid) == expected, 'Capture changed before release intent')
                request = {'id': uuid.uuid4().hex, 'kind': 'delete_capture', 'route': route,
                           'snapshotId': sid, 'recordSha256': expected, 'startedNs': time.time_ns()}
                requests.append(request)
                state['phase'] = 'releasing_captures'
                save()
                status, _ = api.call('DELETE', route, timeout=120)
                require(status == 204, 'Capture DELETE not confirmed; preserve intent')
                require(api.call('GET', route)[0] == 404 and record(sid) is None,
                        'Capture remains or local/API outcome differs')
                method = 'DELETE_204_GET_404_AND_RECORD_ABSENT'
            snapshots.remove(sid)
            if request is not None:
                requests.remove(request)
                state['operations'].append({**request, 'confirmedBy': method, 'finishedNs': time.time_ns()})
            state.setdefault('releasedSnapshots', []).append({'snapshotId': sid, 'recordSha256': expected,
                                                               'confirmedBy': method})
            save()
        empty()
        state['phase'] = 'quiesced'
        state['captureReleaseComplete'] = True
        save()
    except Exception as error:
        state['captureReleaseComplete'] = False
        state['captureReleaseError'] = {'type': type(error).__name__,
                                        'reason': str(error)[:600] if isinstance(error, RuntimeError)
                                        else 'Inspect preserved release intent and record'}
        if requests:
            state['phase'] = 'needs_reconciliation'
        save()
    return state


class Cohort:
    def __init__(self, api, state, persist, observe, execute, capacity, snapshot, *, run_id=None,
                 residency_gate=None, mutation_guard=None):
        require(quiescent(state), 'Previous batch is not quiescent; no new run allowed')
        self.api, self.persist = api, persist
        self.observe, self.execute = observe, execute
        self.capacity, self.snapshot = capacity, snapshot
        self.residency_gate, self.mutation_guard = residency_gate, mutation_guard
        self.state = copy.deepcopy(state)
        self.run_id = run_id or uuid.uuid4().hex
        require(re.fullmatch('[0-9a-f]{32}', self.run_id), 'Invalid batch identity')
        self.state.update(runId=self.run_id, phase='active', snapshots=[], operations=[],
                          samples=[], workloads=[], lifecyclePassed=False)
        self.persist(self.state)

    def save(self):
        self.state['outcomeUncertain'] = bool(self.state['openRequests'])
        self.persist(self.state)

    def owned(self, sid):
        status, body = self.api.call('GET', '/sandboxes/' + identifier(sid))
        if status == 404:
            return None
        require(status == 200 and isinstance(body, dict)
                and body.get('sandboxID') == sid
                and isinstance(body.get('metadata'), dict)
                and body['metadata'].get('cow_batch') == self.run_id,
                'Guest identity or batch metadata differs; do not mutate it')
        return body

    def mutation(self, kind, route, body, decode, timeout):
        if kind != 'delete' and self.mutation_guard is not None:
            self.mutation_guard()
        require(not self.state['openRequests'] or kind == 'delete',
                'Unresolved operation; no new allocation/capture permitted')
        request = {'id': uuid.uuid4().hex, 'kind': kind, 'route': route,
                   'startedNs': time.time_ns()}
        self.state['openRequests'].append(request)
        self.save()  # Must reach durable storage before the HTTP request.
        start = time.monotonic()
        method = 'DELETE' if kind == 'delete' else 'POST'
        status, reply = self.api.call(method, route, body, timeout=timeout)
        ack = acknowledged_identity(kind, status, reply)
        if ack is not None:
            request.update(ack=ack, responseHttpStatus=status)
            self.save()
        # Decoder validates every result before the intent is cleared. It may
        # register known children even if the rest of a multi-result is invalid.
        result = decode(status, reply)
        self.state['operations'].append({**request, 'httpStatus': status,
                                        'seconds': time.monotonic() - start,
                                        'finishedNs': time.time_ns()})
        self.state['openRequests'].remove(request)
        self.save()
        return result

    def add_guest(self, body):
        require(isinstance(body, dict), 'Creation result is not an object')
        sid = identifier(body.get('sandboxID'))
        # Registration precedes the independent GET, so known identities survive
        # a GET failure and are still available for ownership-checked cleanup.
        require(sid not in self.state['sandboxIds'], 'Repeated creation identity')
        self.state['sandboxIds'].append(sid)
        self.save()
        require(self.owned(sid) is not None, 'New Guest vanished before ownership confirmation')
        return sid

    def create(self, route, body):
        self.capacity('cold' if route == '/sandboxes-cold' else 'restore')
        def decode(status, reply):
            require(status == 201, 'Creation not confirmed; retain intent without retry')
            return self.add_guest(reply)
        return self.mutation('create', route, body, decode, 600)

    def capture(self, sid):
        require(self.owned(sid) is not None, 'Capture source missing')
        def decode(status, reply):
            require(status in (200, 201) and isinstance(reply, dict), 'Capture outcome unresolved')
            snapshot_id = identifier(reply.get('snapshotID'))
            self.state['snapshots'].append(snapshot_id)
            self.save()
            return snapshot_id
        result = self.mutation('capture', '/sandboxes/' + sid + '/snapshots',
                               {'name': 'cow-batch-' + self.run_id}, decode, 300)
        # This is artifact verification, not an uncertain API request. On failure
        # the committed snapshot remains listed and its UB base stays retained.
        self.state.setdefault('snapshotEvidence', []).append(self.snapshot(result))
        self.save()
        return result

    def fork_one(self, sid, timeout=1800):
        require(type(timeout) is int and 1 <= timeout <= 7200, 'Explicit bounded Fork lifetime required')
        require(self.owned(sid) is not None, 'Fork source missing')
        self.capacity('fork')
        def decode(status, reply):
            require(status == 201 and isinstance(reply, list) and len(reply) == 1,
                    'Fork response unresolved; retain request intent')
            entry = reply[0]
            require(isinstance(entry, dict) and entry.get('error') is None
                    and isinstance(entry.get('sandbox'), dict), 'Fork child not confirmed')
            return self.add_guest(entry['sandbox'])
        return self.mutation('fork', '/sandboxes/' + sid + '/fork',
                             {'count': 1, 'timeout': timeout}, decode, 600)

    def delete(self, sid):
        route = '/sandboxes/' + sid
        previous = [r for r in self.state['openRequests'] if r['kind'] == 'delete' and r['route'] == route]
        present = self.owned(sid)
        if present is None:
            self.state['sandboxIds'].remove(sid)
            for request in previous:
                self.state['openRequests'].remove(request)
                self.state['operations'].append({**request, 'reconciledBy': 'GET_404', 'finishedNs': time.time_ns()})
            self.save()
            return
        require(not previous, 'Previous delete remains unresolved; no second DELETE sent')
        def decode(status, reply):
            require(status in (200, 204, 404), 'Delete request not confirmed')
            # A successful DELETE response alone is insufficient for retirement.
            require(self.owned(sid) is None, 'Guest remains visible after deletion')
            self.state['sandboxIds'].remove(sid)
        self.mutation('delete', route, None, decode, 120)

    def sample(self, phase, sids):
        for sid in sids:
            require(self.owned(sid) is not None, 'Sampling Guest disappeared')
        try:
            sample = self.observe(phase, sids)
        except Exception as error:
            sample = {'phase': phase, 'available': False, 'errorType': type(error).__name__}
        self.state['samples'].append(sample)
        self.save()

    @classmethod
    def recovery(cls, api, state, persist):
        require(state.get('version') == 1 and re.fullmatch('[0-9a-f]{32}', state.get('runId', '')),
                'No recognized existing batch to reconcile')
        require(isinstance(state.get('sandboxIds'), list) and len(state['sandboxIds']) <= 3
                and len(set(state['sandboxIds'])) == len(state['sandboxIds'])
                and isinstance(state.get('openRequests'), list) and len(state['openRequests']) <= 16
                and isinstance(state.get('snapshots'), list) and len(state['snapshots']) <= 1
                and isinstance(state.get('operations'), list), 'Malformed or oversized existing batch')
        for sid in state['sandboxIds'] + state['snapshots']:
            identifier(sid)
        instance = cls.__new__(cls)
        instance.api, instance.persist = api, persist
        instance.mutation_guard = None
        instance.state, instance.run_id = copy.deepcopy(state), state['runId']
        return instance

    def recover_owned(self):
        # Only an actual response persisted before interruption can resolve a
        # POST. Empty inventory and client timeout are never acknowledgments.
        for request in list(self.state['openRequests']):
            ack = request.get('ack')
            if ack is None:
                continue
            kind, status = request.get('kind'), request.get('responseHttpStatus')
            try:
                if kind in ('create', 'fork'):
                    require(status == 201 and set(ack) == {'sandboxIds'}
                            and isinstance(ack['sandboxIds'], list) and len(ack['sandboxIds']) == 1,
                            'Malformed creation acknowledgment')
                    sid = identifier(ack['sandboxIds'][0])
                    present = self.owned(sid)
                    if present is not None and sid not in self.state['sandboxIds']:
                        require(len(self.state['sandboxIds']) < 3, 'Recovery child limit exceeded')
                        self.state['sandboxIds'].append(sid)
                elif kind == 'capture':
                    require(status in (200, 201) and set(ack) == {'snapshotId'}, 'Malformed capture acknowledgment')
                    snapshot_id = identifier(ack['snapshotId'])
                    require(not self.state['snapshots'] or self.state['snapshots'] == [snapshot_id],
                            'Capture acknowledgment differs from recorded snapshot')
                    self.state['snapshots'] = [snapshot_id]
                else:
                    continue
                self.state['openRequests'].remove(request)
                self.state['operations'].append({**request, 'reconciledBy': 'DURABLE_API_RESPONSE',
                                                 'reconciledNs': time.time_ns()})
                self.save()
            except Exception as error:
                self.state.setdefault('reconciliationErrors', []).append({'requestId': request.get('id'),
                                                                          'errorType': type(error).__name__})
                self.save()
        self.cleanup()
        return self.state

    def cleanup(self):
        for sid in list(reversed(self.state['sandboxIds'])):
            try:
                self.delete(sid)
            except Exception as error:
                self.state.setdefault('cleanupErrors', []).append({
                    'sandboxId': sid, 'type': type(error).__name__})
                self.save()
        if not self.state['sandboxIds'] and not self.state['openRequests']:
            try:
                require(self.api.call('GET', '/v2/sandboxes?limit=1') == (200, []),
                        'Final running/paused inventory is not empty')
                self.state['phase'] = 'quiesced'
            except Exception as error:
                self.state['phase'] = 'inventory_unconfirmed'
                self.state['inventoryError'] = type(error).__name__
        else:
            self.state['phase'] = 'needs_reconciliation'
        self.save()

    def run(self, image):
        """One cold parent, one capture/restore and one Fork, then two children.

        Captures precede the public workload. Parent is removed before sampling
        the children. Snapshots are deliberately retained for recovery; retirement
        must not be attempted while they remain referenced.
        """
        try:
            require(self.api.call('GET', '/v2/sandboxes?limit=1') == (200, []),
                    'Service must initially have no running or paused Guests')
            meta = {'cow_batch': self.run_id}
            parent = self.create('/sandboxes-cold', {
                'image': image, 'cpuCount': 1, 'memoryMB': 512, 'secure': True,
                'autoPause': False, 'allowInternetAccess': False, 'timeout': 1800,
                'metadata': meta})
            snap = self.capture(parent)
            child1 = self.create('/v2/sandboxes', {
                'templateID': snap, 'timeout': 1800, 'autoPause': False,
                'allow_internet_access': False, 'metadata': meta})
            child2 = self.fork_one(child1)
            self.delete(parent)
            children = [child1, child2]
            self.sample('before_workload', children)
            results = self.execute(children, self.run_id,
                                   lambda active=None: self.sample(
                                       'during_workload_unspecified' if active is None else
                                       'both_replaying_at_sample_start' if len(active) == 2 else
                                       'mixed_replay_at_sample_start', children))
            self.state['workloads'] = results
            self.save()
            require(len(results) == 2 and all(r.get('passed') is True for r in results),
                    'One or more workloads or private-write isolation checks failed')
            identities = {(r['result']['catalogSha256'], r['result']['sqlSha256'],
                           r['result']['fileCount'], r['result']['fileBytes']) for r in results}
            require(len(identities) == 1, 'Children did not execute the same public workload')
            if self.residency_gate is None:
                self.sample('after_workload', children)
            else:
                self.state['pairedWindow'] = self.residency_gate(self, children)
                self.save()
            self.state['lifecyclePassed'] = True
            self.save()
        except (Exception, KeyboardInterrupt) as error:
            self.state['failure'] = {'type': type(error).__name__,
                                     'reason': str(error)[:800] if isinstance(error, RuntimeError)
                                     else 'Inspect local operation logs and preserved journal'}
        finally:
            self.cleanup()
        return self.state
