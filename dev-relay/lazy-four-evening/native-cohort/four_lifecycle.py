"""Compose four bounded one-template journals without widening their ownership."""
import copy
import concurrent.futures
import threading
import hashlib


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def empty_state(context):
    return {'version': 1, 'phase': 'prepared', 'openRequests': [], 'sandboxIds': [],
            'outcomeUncertain': False, 'runtimeContext': copy.deepcopy(context)}


class FourLifecycle:
    def __init__(self, engine, api, run_id, context, persist, capacity, snapshot, *, initial=None):
        self.engine, self.api, self.run_id = engine, api, run_id
        self.context, self.persist = context, persist
        self.capacity, self.snapshot = capacity, snapshot
        self.cases = {}
        if initial is not None:
            need(set(initial) <= {str(i) for i in range(4)}, 'Unexpected saved case scope')
            for index, state in initial.items():
                need(state.get('runtimeContext') == context, 'Saved Runtime context differs')
                self.cases[int(index)] = engine.Cohort.recovery(api, state, self.writer(int(index)))

    def writer(self, index):
        return lambda state: self.persist(index, state)

    def guard(self):
        need(all(not case.state['openRequests'] for case in self.cases.values()),
             'An uncertain request in any case blocks all new creations')

    def begin_case(self, index):
        self.guard()
        need(index in range(4) and index not in self.cases, 'Repeated case initialization refused')
        nonce = hashlib.sha256((self.run_id + ':' + str(index)).encode()).hexdigest()[:32]
        case = self.engine.Cohort(self.api, empty_state(self.context), self.writer(index),
            None, None, self.capacity, lambda sid: self.snapshot(index, sid), run_id=nonce,
            mutation_guard=self.guard)
        self.cases[index] = case
        return case

    def prepare_parents(self, images):
        need(len(images) == 4 and not self.cases, 'Four fresh native parent cases required')
        need(self.api.call('GET', '/v2/sandboxes?limit=1') == (200, []), 'New Runtime inventory must be empty')
        templates = []
        for index, image in enumerate(images):
            case = self.begin_case(index)
            resource = image['resources']
            need(resource['memory_mib'] == 4096 and resource['cpu_count'] == 2, 'Reference resources differ')
            sid = case.create('/sandboxes-cold', {'image': image['ociReference'], 'cpuCount': 2, 'memoryMB': 4096,
                'secure': True, 'autoPause': False, 'allowInternetAccess': False, 'timeout': 1800,
                'metadata': {'cow_batch': case.run_id, 'cow_four_index': str(index)}})
            template = case.capture(sid)
            case.delete(sid)
            case.state['phase'] = 'quiesced'
            case.save()
            templates.append({'templateIndex': index, 'nativeTemplateId': template,
                              'sourceImage': image['sourceImage'], 'resources': resource,
                              'snapshotEvidence': copy.deepcopy(case.state['snapshotEvidence'][0])})
        return templates

    def restore_pairs(self, templates, fork=False, parallel=False):
        if parallel:return self.parallel_forks(templates)
        need(len(templates) == 4 and not self.cases, 'Four fresh replay cases required')
        need(self.api.call('GET', '/v2/sandboxes?limit=1') == (200, []), 'New Runtime inventory must be empty')
        jobs = []
        for index, template in enumerate(templates):
            need(template['templateIndex'] == index, 'Template ordering differs')
            case = self.begin_case(index)
            for slot in (0, 1):
                if fork and slot == 1:
                    sid = case.fork_one(parent_sid, timeout=7200)
                else:
                    sid = case.create('/v2/sandboxes', {'templateID': template['nativeTemplateId'],
                        'timeout': 7200, 'autoPause': False, 'allow_internet_access': False, 'secure': True,
                        'metadata': {'cow_batch': case.run_id, 'cow_four_index': str(index), 'cow_four_slot': str(slot)}})
                if slot == 0: parent_sid = sid
                jobs.append({'templateIndex': index, 'slot': slot, 'sandboxId': sid,
                             'nativeTemplateId': template['nativeTemplateId'], 'caseRunId': case.run_id})
        need(len(jobs) == len({job['sandboxId'] for job in jobs}) == 8, 'Eight distinct Guests required')
        return jobs

    def parallel_forks(self,templates):
        """Four admitted owned parents, at most one in-flight Fork per parent.

        The original global unknown-operation guard is restored before returning.
        An error stops later admission approvals; already approved requests may
        still reach the server, remain journaled and are joined without retry.
        """
        need(len(templates)==4 and not self.cases,'Four fresh parent cases required')
        need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'Runtime inventory must be empty')
        self.capacity('fork-burst')
        parents=[];jobs=[]
        for index,template in enumerate(templates):
            need(template['templateIndex']==index,'Template order differs')
            case=self.begin_case(index)
            sid=case.create('/v2/sandboxes',{'templateID':template['nativeTemplateId'],'timeout':7200,
                'autoPause':False,'allow_internet_access':False,'secure':True,
                'metadata':{'cow_batch':case.run_id,'cow_four_index':str(index),'cow_four_slot':'0'}})
            parents.append((index,case,sid,template))
            jobs.append({'templateIndex':index,'slot':0,'sandboxId':sid,'nativeTemplateId':template['nativeTemplateId'],'caseRunId':case.run_id})
        self.guard();self.capacity('fork-burst')
        halt=threading.Event();admission=threading.Lock()
        def allowed():
            with admission:need(not halt.is_set(),'Fork burst stopped after an uncertain or failed request')
        def fork(item):
            index,case,parent,template=item
            try:
                child=case.fork_one(parent,timeout=7200)
                return {'templateIndex':index,'slot':1,'sandboxId':child,'nativeTemplateId':template['nativeTemplateId'],'caseRunId':case.run_id}
            except BaseException:
                halt.set()
                raise
        previous=[case.mutation_guard for _,case,_,_ in parents]
        errors=[]
        try:
            for _,case,_,_ in parents:case.mutation_guard=allowed
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures=[pool.submit(fork,item) for item in parents]
                for future in futures:
                    try:jobs.append(future.result())
                    except Exception as error:errors.append(type(error).__name__)
        finally:
            halt.set()
            for (_,case,_,_),guard in zip(parents,previous):case.mutation_guard=guard
        need(not errors,'Native Fork burst failed; preserve per-case request journals: '+','.join(errors))
        need(len(jobs)==len({job['sandboxId'] for job in jobs})==8,'Eight confirmed distinct Guests required')
        return sorted(jobs,key=lambda job:(job['templateIndex'],job['slot']))


    def owned(self, sid):
        matches = [case for case in self.cases.values() if sid in case.state['sandboxIds']]
        need(len(matches) == 1, 'Guest not uniquely bound to this four-case batch')
        return matches[0].owned(sid)

    def cleanup(self):
        # Each existing engine can reconcile only its own durable response and
        # at most three Guests. Never replace unknown POSTs with empty inventory.
        for case in self.cases.values():
            case.recover_owned()
        clean = all(not case.state['sandboxIds'] and not case.state['openRequests'] for case in self.cases.values())
        if clean:
            clean = self.api.call('GET', '/v2/sandboxes?limit=1') == (200, [])
        if clean:
            # Earlier individual cleanup may see another case's still-running
            # Guest. Only after the final global-empty check can all be quiesced.
            for case in self.cases.values():
                case.state['phase'] = 'quiesced'
                case.save()
        return {'ownedGuestsReleased': clean,
                'outcomeUncertain': any(case.state['openRequests'] for case in self.cases.values()),
                'remainingSandboxIds': [sid for case in self.cases.values() for sid in case.state['sandboxIds']]}

    def release_captures(self, record):
        result = self.cleanup()
        need(result['ownedGuestsReleased'] and not result['outcomeUncertain'], 'Cleanup must complete before capture release')
        for index, case in self.cases.items():
            self.engine.release_captures(self.api, case.state, self.writer(index), lambda sid: record(index, sid))
            need(case.state.get('captureReleaseComplete') is True, 'Owned capture release remains unconfirmed')
