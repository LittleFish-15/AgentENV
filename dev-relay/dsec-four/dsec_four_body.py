"""A-only DSec four-template replay after the repaired real-template smoke.

Embedded helpers are pinned by the packaging manifest. This entry never updates
services or releases base images/captures. It requires a human-started read-only
root observer; both terminals remain attached and have bounded lifetimes.
"""
import argparse, base64, copy, hashlib, json, os, re, signal, socket, stat, sys, threading, time, types, uuid, zlib
from pathlib import Path

ROOT = Path('/home/jwk/agent')
D = ROOT / 'deployments/agentenv-dsec-hostfile-v1'
WORK = D / 'dsec-four-v1'
INPUTS = ROOT / 'builds/native-four-inputs-v1'
CORE = '268104ecc65080d776c2301e09e7902686ac4253'
UNIT = 'jwk-aenv-dsec-hostfile-v1-node-a.service'
PROVIDER = 'jwk-dsec-file-provider-node-a-v1.service'
INPUT_RETURN_SHA = '53d6c4c870681f81662b1a8b45df99e38c1931abacc3ef59b83c710684ba652a'
REPAIR_ENTRY_SHA = 'e53ea9250227b7e59ea547031e32a0e75797f8d3395343f48367cdbe37bf9c3b'
PAYLOAD = {}
MODULES = {}


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def module(name):
    if name not in MODULES:
        row = PAYLOAD[name]
        raw = zlib.decompress(base64.b64decode(row['z64'], validate=True))
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'Embedded helper differs')
        value = types.ModuleType('dsec_' + name)
        value.__file__ = str(WORK / (name + '.py'))
        exec(compile(raw, value.__file__, 'exec'), value.__dict__)
        MODULES[name] = value
    return MODULES[name]


def base_class():
    field = module('four_cohort')
    field.D = D
    field.CORE = CORE
    field.module = module
    return field


def input_contract(rt):
    raw = rt.read(INPUTS / 'return.json', 4 * 1024**2)
    need(hashlib.sha256(raw).hexdigest() == INPUT_RETURN_SHA, 'Retained input receipt changed')
    receipt = json.loads(raw)
    need(receipt['status'] == 'FOUR_NATIVE_IMAGES_AND_BINARIES_PREPARED_NOT_DEPLOYED', 'Retained inputs incomplete')
    seed = rt.load(D / 'rootfs-inputs.json')
    selected_raw = rt.read(INPUTS / 'selection.private.json', 8 * 1024**2)
    selection = json.loads(selected_raw)['selected']
    need(len(selection) == len(seed['images']) == len(receipt['cases']) == 4, 'Four retained cases required')
    need(seed.get('node') == 'node-a' and seed.get('coreCommit') == receipt['coreCommit'], 'Source provenance differs')
    for index, (case, image, source) in enumerate(zip(selection, seed['images'], receipt['cases'])):
        need(image['templateIndex'] == source['templateIndex'] == index and
             image['instanceId'] == source['instanceId'] == case['case']['instance_id'] and
             image['sourceImage'] == source['sourceImage'] and image['resources'] == source['resources'] and
             image['replaySha256'] == source['replaySha256'] == case['case']['replay_sha256'], 'Retained case differs')
        replay = base64.b64decode(case['replayBase64'], validate=True)
        need(hashlib.sha256(replay).hexdigest() == source['replaySha256'], 'Private replay content differs')
        steps, _ = module('four_replay').steps_from(replay)
        need(len(steps) == case['executedStepCount'], 'Private replay step count differs')
        need(image['resources']['cpu_count'] == 2 and image['resources']['memory_mib'] == 4096,
             'Expected original two CPU/four GiB resources')
        need(image['ociReference'] == 'ocidir://' + source['ociDirectory'] + '@' + source['ociDigest'],
             'Retained OCI reference differs')
    return seed, selection, receipt, hashlib.sha256(selected_raw).hexdigest()


def runtime_contract(rt, require_smoke=True):
    installation = rt.load(D / 'installation.json')
    proof = rt.load(D / 'updates/pmem-id-fix-v1/activation-proof.json')
    need(installation.get('commit') == CORE and proof.get('coreCommit') == CORE and
         proof.get('entrySha256') == REPAIR_ENTRY_SHA, 'Repaired candidate activation required')
    definition = rt.load(D / 'definition-native.json')
    api = rt.Api(D, UNIT, definition['apiPort'])
    context = {'unit': UNIT, 'pid': api.pid, 'ticks': api.ticks, 'configSha256': api.config_sha,
               'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    need(context == proof['runtimeContext'] and api.port == 18084, 'Runtime changed since repair activation')
    for name, pin in installation['binaries'].items():
        need(rt.digest_file(D / 'bin' / name) == pin, 'Installed binary changed: ' + name)
    need(proof['serverSha256'] == installation['binaries']['server'], 'Candidate server provenance differs')
    if require_smoke:
        smoke = rt.load(D / 'dsec-real-template-smoke-v2/return.json')
        need(smoke.get('status') == 'DSEC_REAL_TEMPLATE_RESTORE_PAIR_PASSED_GUESTS_RELEASED' and
             smoke.get('runtimeContext') == context and smoke.get('coreCommit') == CORE and
             smoke.get('ownedGuestsReleased') is True and smoke.get('baseUnchanged') is True,
             'Repaired real-template lifecycle must pass before four-template expansion')
    pin = definition['rootfsBinding']
    raw = rt.read(pin['path'])
    need(hashlib.sha256(raw).hexdigest() == pin['sha256'], 'Binding catalog changed')
    binding = json.loads(raw)
    need(binding.get('catalogVersion') == 1 and len(binding.get('bindings', [])) == 4, 'Four bindings required')
    need(all(b.get('version') == 5 and b.get('lowerFilesystem') == 'ext4' for b in binding['bindings']),
         'Host-file ext4 v5 bindings required')
    return api, context, binding


def build_run(args):
    field = base_class()
    class Run(field.FieldBatch):
        def __init__(self):
            self.args = args
            self.node = 'node-a'
            self.rt, self.engine = module('four_runtime'), module('cohort_engine')
            self.lifecycle_module = module('four_lifecycle')
            self.replay = module('four_replay')
            self.observer = module('dsec_observer')
            self.metrics = module('four_metrics').Metrics()
            self.seed, self.selection, self.receipt, self.selection_sha = input_contract(self.rt)
            self.api, self.context, self.binding = runtime_contract(self.rt)
            for image, binding, source in zip(self.seed['images'], self.binding['bindings'], self.receipt['cases']):
                need(image['sourceImage'] == binding['sourceImage'] and len(binding['layers']) == 1,
                     'Bound source differs')
                need(binding['layers'][0]['sha256'] == source['nativeImage']['sha256'] and
                     binding['layers'][0]['bytes'] == source['nativeImage']['bytes'], 'Bound base differs')
            self.root = WORK
            self.root.mkdir(mode=0o700, exist_ok=True)
            need(self.root.resolve(strict=True) == self.root and self.root.stat().st_uid == 1204, 'Work root changed')
            self.phase = 'parents' if args.mode == 'parents' else args.scenario
            self.work = self.root / self.phase
            self.run_id = uuid.uuid4().hex
            self.states, self.jobs, self.state = {}, [], {'samples': []}
            self.stop, self.mutex = threading.Event(), threading.RLock()
            self.credentials, self.lifecycle = None, None
            self.base_pins = self.observer.pin_base_files([INPUTS / f'case-{i}/raw/rootfs.ext4' for i in range(4)])
            self.allowed_lowers = sorted({Path(layer['path']) for image in self.seed['images'] for layer in image['layers']})
            self.root_sample_cursor = None
            self.heavy_at = 0
            self.api_errors = self.root / 'api-errors.jsonl'
            original_call = self.api.call
            def recorded(method, path, body=None, timeout=30):
                status, reply = original_call(method, path, body, timeout)
                if status >= 400 and status != 404:
                    details = {k: reply[k] for k in ('message', 'error', 'code', 'detail') if k in reply} if isinstance(reply, dict) else {}
                    text = re.sub(r'e2b_[A-Za-z0-9._~-]+', '<redacted>', json.dumps(details))
                    with self.api_errors.open('a') as stream:
                        stream.write(json.dumps({'method': method, 'path': path, 'status': status, 'details': text[:3000]}) + '\n')
                return status, reply
            self.api.call = recorded

        def cancel_check(self):
            need(not self.stop.is_set(), 'Cohort interrupted')
            if args.mode == 'replay':
                ready = self.rt.load(WORK / 'observer-live.json')
                need(ready.get('planSha256') == self.observer_plan_sha and ready.get('observerRunId') == self.observer_run and
                     0 <= time.monotonic() - ready['monotonic'] < 150, 'Root observer stopped or changed; stop replay')

        def persist_case(self, index, value):
            super().persist_case(index, value)
            if hasattr(self, 'observer_run'):
                ids = [sid for state in self.states.values() for sid in state['sandboxIds']]
                self.observer_request('lifecycle_transition', ids)

        def observer_request(self, phase, ids):
            self.rt.save(WORK / 'observation-request.json', {'version': 1, 'observerRunId': self.observer_run,
                'phase': phase, 'runId': self.run_id, 'runtimeContext': self.context,
                'sandboxIds': ids, 'jobs': copy.deepcopy(self.jobs), 'monotonic': time.monotonic()})

        def sample(self, phase, ids):
            self.cancel_check()
            for sid in ids:
                need(self.owned(sid) is not None, 'Guest missing during observation')
            self.observer_request(phase, ids)
            # Privileged observation is a separate read-only process. Do not
            # collect the same heavy RAM/cache scan twice or invent zeros here.
            latest = WORK / 'observer-latest.json'
            if phase in ('before_replay', 'after_replay'):
                deadline = time.monotonic() + 120
                while time.monotonic() < deadline:
                    self.cancel_check()
                    if latest.exists():
                        observed = self.rt.load(latest)
                        if (observed.get('observerRunId') == self.observer_run and observed.get('runId') == self.run_id
                                and observed.get('phase') == phase and observed.get('heavySample') is True):
                            break
                    need(not self.stop.wait(1), 'Interrupted while waiting for phase observation')
                else:
                    raise RuntimeError('Bounded phase observation unavailable; no implicit measurement acceptance')
            if latest.exists():
                value = self.rt.load(latest)
                if value.get('observerRunId') == self.observer_run and value.get('runId') == self.run_id:
                    if value['endNs'] != self.root_sample_cursor:
                        self.root_sample_cursor = value['endNs']
                        self.state['samples'] = [value]
                        self.metrics.add(value, self.jobs)
                        return value
            value = {'startNs': time.time_ns(), 'endNs': time.time_ns(), 'phase': phase,
                     'observerPending': True, 'ram': {'available': False, 'guests': []}}
            self.state['samples'] = [value]
            return value

        def cleanup_existing(self):
            return super().cleanup_existing()

        def wait_observer(self):
            plan = {'version': 1, 'runtimeContext': self.context, 'coreCommit': CORE,
                    'entrySha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'baseFiles': self.base_pins, 'allowedLowers': [str(p) for p in self.allowed_lowers],
                    'sourceSelectionSha256': self.selection_sha, 'maxGuests': 8,
                    'observerRunId': uuid.uuid4().hex, 'maxSeconds': 10800}
            path = WORK / 'observer-plan.json'
            need(not path.exists(), 'Previous observation plan retained; no blind observer restart')
            self.rt.save(path, plan)
            self.observer_plan_sha = hashlib.sha256(self.rt.read(path)).hexdigest()
            self.observer_run = plan['observerRunId']
            self.observer_request('before_restore', [])
            print(root_bootstrap(plan['entrySha256'], self.observer_plan_sha), flush=True)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                path = WORK / 'observer-live.json'
                if path.exists():
                    ready = self.rt.load(path)
                    if ready.get('planSha256') == self.observer_plan_sha:
                        self.cancel_check()
                        return
                need(not self.stop.wait(1), 'Interrupted while waiting for read-only observer')
            raise RuntimeError('Root observer not started within 600 seconds; no replay Guest created')

    return Run()


def root_bootstrap(entry_sha, plan_sha):
    # Pins the entire embedded executable, not a mutable imported module tree.
    entry = str(Path(__file__).resolve())
    return ("BEGIN_DSEC_FOUR_READONLY_ROOT\n/usr/bin/python3 -I -B - <<'DSEC_FOUR_READONLY_ROOT'\n"
            "import hashlib,os,runpy,socket,stat,sys\nfrom pathlib import Path\n"
            "assert os.geteuid()==0 and socket.gethostname()=='server1'\n"
            f"p=Path({entry!r});assert p.resolve(strict=True)==p and p.is_relative_to(Path('/home/jwk/agent'))\n"
            "s=p.stat();assert stat.S_ISREG(s.st_mode) and s.st_uid==1204 and s.st_size<1048576\n"
            f"raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()=={entry_sha!r}\n"
            f"sys.argv=[str(p),'observe','--plan-sha',{plan_sha!r}]\n"
            "exec(compile(raw,str(p),'exec'),{'__name__':'__main__','__file__':str(p)})\n"
            "DSEC_FOUR_READONLY_ROOT\nEND_DSEC_FOUR_READONLY_ROOT")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'parents', 'replay', 'cleanup', 'observe', 'report'))
    parser.add_argument('--scenario', choices=('parents', 'single-a'), default='single-a')
    parser.add_argument('--plan-sha')
    args = parser.parse_args()
    if args.mode == 'plan':
        print(json.dumps({'scope': 'single_host_DSec_four_templates_two_Guests_each',
            'requiresRepairedSmokePass': True, 'noUB': True, 'sourceImagesRebuilt': False,
            'maxConcurrentGuests': 8, 'GuestMiB': 4096, 'newCleanParentCaptures': 4,
            'servicesChanged': False, 'snapshotsDeleted': False, 'globalPhysicalSavingBytes': None}));return 0
    need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and socket.gethostname() == 'server1',
         'Use intended A ARM64 host')
    if args.mode == 'observe':
        need(os.getuid() == os.geteuid() == 0, 'Read-only observer requires root')
        return module('dsec_root_observer').run(globals(), args.plan_sha)
    need(os.getuid() == os.geteuid() == 1204, 'Use ordinary jwk')
    os.umask(0o077)
    if args.mode == 'report':
        return module('dsec_four_finish').report(globals())
    import fcntl
    lock = os.open(D / 'cohort.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    need(stat.S_ISREG(os.fstat(lock).st_mode) and os.fstat(lock).st_uid == 1204, 'Cohort lock differs')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    batch = None
    try:
        args.release_captures = False
        batch = build_run(args)
        def interrupted(*_):
            batch.stop.set()
            raise KeyboardInterrupt('Operator interrupted DSec cohort')
        for name in ('SIGTERM', 'SIGHUP'):
            signal.signal(getattr(signal, name), interrupted)
        if args.mode == 'parents':
            result = batch.create_templates()
            batch.rt.save(WORK / 'parents-return.json', result)
        elif args.mode == 'replay':
            batch.wait_observer()
            try:
                result = batch.run_replay()
            finally:
                batch.observer_request('owner_finished', [])
                deadline = time.monotonic() + 120
                while not (WORK / 'observer-return.json').exists() and time.monotonic() < deadline:
                    time.sleep(1)
            module('dsec_four_finish').report(globals())
        else:
            result = batch.cleanup_existing()
        print(json.dumps(result, indent=2))
        passed = result.get('status') in ('FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED',
                                          'NATIVE_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED')
        return 0 if passed or (args.mode == 'cleanup' and result.get('ownedGuestsReleased') is True) else 1
    except (Exception, KeyboardInterrupt) as error:
        result = {'status': 'STOPPED_DSEC_FOUR_PRESERVE_JOURNALS', 'errorType': type(error).__name__,
                  'reason': re.sub(r'e2b_[A-Za-z0-9._~-]+', '<redacted>', str(error))[:1200]}
        if batch is not None and batch.lifecycle is not None:
            try: result['cleanup'] = batch.lifecycle.cleanup()
            except Exception as cleanup: result['cleanupErrorType'] = type(cleanup).__name__
        print(json.dumps(result, indent=2))
        return 1
    finally:
        os.close(lock)


if __name__ == '__main__':
    raise SystemExit(main())
