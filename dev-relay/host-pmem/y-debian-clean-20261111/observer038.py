"""Read-only FC, block and host counters with scoped host-kernel profiling.

Snapshots enclose client phase timers and are not atomic across processes.
The decoded profile must be cropped to the client's CLOCK_MONOTONIC windows.
This observer never opens a memory block device or retains its page cache.
"""

import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import time

P = pathlib.Path
BASE = P('/home/jwk/aenv-y-clean-20261111')
UNIT = 'jwk-aenv-y-clean-20261111.service'
GROUP = 'Y_no_anchor'


def procstat(raw):
    fields = raw.rsplit(')', 1)[1].split()
    if len(fields) < 20:
        raise ValueError('Incomplete proc stat')
    return {
        'state': fields[0], 'minflt': int(fields[7]),
        'majflt': int(fields[9]), 'utime': int(fields[11]),
        'stime': int(fields[12]), 'starttime': int(fields[19]),
        'guest_ticks': int(fields[40]) if len(fields) > 40 else None,
    }


def schedstat(raw):
    values = raw.split()
    if len(values) != 3:
        raise ValueError('Expected three schedstat counters')
    values = [int(value) for value in values]
    if any(value < 0 for value in values):
        raise ValueError('Negative schedstat counter')
    return dict(zip(('execution_ns', 'run_delay_ns', 'timeslices'), values))


def selected_vmstat(raw):
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        key, value = fields
        if key in ('pgfault', 'pgmajfault', 'pswpin', 'pswpout') or key.startswith(
            ('pgscan_', 'pgsteal_', 'allocstall', 'workingset_refault_', 'workingset_activate_')
        ):
            result[key] = int(value)
    return result


def changed_rows(current, previous, full=False):
    return ({key: row for key, row in current.items()
             if full or previous.get(key) != row}, list(current))


def thread_inventory_changes(current, previous):
    """Describe observed TID identities; an absent baseline is never zero."""
    result = {}
    for pid, row in current.items():
        now = row.get('schedstat')
        if not row.get('schedstatSampled') or not isinstance(now, dict):
            continue
        old_row = previous.get(pid, {})
        old = old_row.get('schedstat', {})
        baseline = (old_row.get('starttime') == row['starttime'] and
                    old_row.get('schedstatSampled') and old.get('available') and
                    old.get('bindingValid'))
        threads = now.get('threads', {})
        before = old.get('threads', {}) if baseline else {}
        reused = [tid for tid in threads if tid in before and
                  threads[tid]['starttime'] != before[tid]['starttime']]
        result[pid] = {
            'processStarttime': row['starttime'], 'baselineObserved': bool(baseline),
            'currentBindingValid': now.get('bindingValid'),
            'currentCompleteForListedTids': now.get('completeForListedTids'),
            'observedTids': list(threads),
            'newTidsSincePreviousObservation':
                [tid for tid in threads if tid not in before or tid in reused] if baseline else None,
            'missingTidsSincePreviousObservation':
                [tid for tid in before if tid not in threads] if baseline else None,
            'reusedTids': reused if baseline else None,
            'unavailableTids': now.get('unavailableTids'),
            'counterBaselinePolicy': 'Missing/unobserved TID counters are unknown, never zero',
        }
    return result


def validate_event(event):
    if not isinstance(event, dict) or event.get('group') != GROUP:
        raise ValueError('Unexpected observer group')
    if event.get('phase') not in ('group', 'create', 'pause', 'resume', 'delete'):
        raise ValueError('Unexpected observer phase')
    if event.get('edge') not in ('before', 'after'):
        raise ValueError('Unexpected observer edge')
    ids = event.get('sandboxIds', [])
    if not isinstance(ids, list) or len(ids) > 1000 or any(
        not isinstance(sid, str) or not sid or len(sid) > 128 for sid in ids
    ):
        raise ValueError('Invalid observer sandbox IDs')
    return event


class Observer:
    def __init__(self, directory, pid):
        self.directory = P(directory)
        self.pid = int(pid)
        self.cgroup = P('/sys/fs/cgroup/system.slice') / UNIT
        self.start_offset = (BASE / 'logs/server.log').stat().st_size
        self.offset = self.start_offset
        self.paths = {}
        self.devices = {}
        self.group = None
        self.current_event = None
        self.perf = None
        self.perf_log = None
        self.profile = {}
        self.errors = []
        self.snapshot_last = {}
        self.block_last = {}
        self.sample_block_last = {}
        self.sample_last = {}
        self.last_scan_interval = None
        self.closed = False
        self.tick = 0
        self.samples = (self.directory / 'samples.jsonl').open('x')
        try:
            self.stacks = (self.directory / 'proc-stacks.jsonl').open('x')
        except BaseException:
            self.samples.close()
            raise

    def note(self, operation, error):
        # Keep errors bounded; optional proc files can disappear during VM exit.
        if len(self.errors) < 200:
            self.errors.append({'operation': operation,
                                'type': type(error).__name__, 'message': str(error)[:1000]})

    def read(self, path, limit=50000):
        try:
            with P(path).open() as stream:
                return stream.read(limit)
        except OSError:
            return None

    def thread_stats(self, pid, expected_start):
        process = P('/proc', str(pid))
        before = self.read(process / 'stat')
        if before is None or procstat(before)['starttime'] != expected_start:
            return {'available': False, 'bindingValid': False,
                    'reason': 'process_identity_missing_or_changed'}
        try:
            tasks = sorted((process / 'task').iterdir(), key=lambda task: int(task.name))
        except OSError as error:
            return {'available': False, 'bindingValid': True,
                    'reason': type(error).__name__}
        threads = {}
        unavailable = []
        for task in tasks:
            try:
                identity_raw = self.read(task / 'stat')
                counters_raw = self.read(task / 'schedstat')
                if identity_raw is None or counters_raw is None:
                    unavailable.append(task.name)
                    continue
                identity = procstat(identity_raw)
                counters = schedstat(counters_raw)
                # A TID may be reused while the thread directory is being read.
                last_raw = self.read(task / 'stat')
                if last_raw is None or procstat(last_raw)['starttime'] != identity['starttime']:
                    unavailable.append(task.name)
                    continue
                threads[task.name] = {
                    'tid': int(task.name), 'starttime': identity['starttime'],
                    'comm': (self.read(task / 'comm', 128) or '').strip(), **counters,
                }
            except (ValueError, IndexError, OSError):
                unavailable.append(task.name)
        after = self.read(process / 'stat')
        if after is None or procstat(after)['starttime'] != expected_start:
            return {'available': False, 'bindingValid': False,
                    'reason': 'process_identity_changed_during_thread_read'}
        return {
            'available': bool(threads), 'bindingValid': True,
            'completeForListedTids': not unavailable,
            'listedTids': [task.name for task in tasks], 'unavailableTids': unavailable,
            'threads': threads,
            'sum': {key: sum(row[key] for row in threads.values())
                    for key in ('execution_ns', 'run_delay_ns', 'timeslices')},
            'units': 'execution/run_delay nanoseconds; timeslices count; no tick conversion',
        }

    def scan(self, include_threads=True):
        started = time.monotonic_ns()
        out = {}
        raw = self.read(self.cgroup / 'cgroup.procs', 1024 * 1024)
        if raw is None:
            self.note('scan_cgroup', RuntimeError('Own cgroup.procs unavailable'))
            pids = []
        else:
            pids = sorted(set(raw.split()), key=int)
        for pid in pids:
            process = P('/proc', pid)
            try:
                if process.stat().st_uid != 1002 or self.read(process / 'comm') != 'firecracker\n':
                    continue
                cwd = os.readlink(process / 'cwd')
                if not P(cwd).is_relative_to(BASE / 'fc'):
                    continue
                first = self.read(process / 'stat')
                if first is None:
                    continue
                counters = procstat(first)
                row = {'pid': int(pid), 'cwd': cwd, **counters,
                       'schedstatSampled': include_threads}
                if include_threads:
                    row['schedstat'] = self.thread_stats(pid, counters['starttime'])
                final = self.read(process / 'stat')
                if final is None or procstat(final)['starttime'] != counters['starttime']:
                    continue
                out[pid] = row
            except (OSError, ValueError, IndexError) as error:
                self.note('scan_fc', error)
        self.last_scan_interval = {'startNs': started, 'endNs': time.monotonic_ns(),
                                   'clock': 'CLOCK_MONOTONIC', 'atomic': False}
        return out

    def tail(self):
        path = BASE / 'logs/server.log'
        try:
            if path.stat().st_size < self.offset:
                raise RuntimeError('Server log shrank; refuse to remap a rotated log silently')
            with path.open('rb') as stream:
                stream.seek(self.offset)
                raw = stream.read(16 * 1024**2)
        except OSError as error:
            self.note('tail', error)
            return
        boundary = raw.rfind(b'\n')
        if boundary < 0:
            return
        self.offset += boundary + 1
        for line in raw[:boundary].splitlines():
            try:
                row = json.loads(line)
                fields = row.get('fields') or {}
                context = (row.get('spans') or []) + [row.get('span') or {}]
                root = next((span for span in context if span.get('sandbox_id')), None)
                if root and fields.get('message') == 'using warm firecracker from pool':
                    cwd = fields.get('pool_work_dir')
                    if isinstance(cwd, str) and P(cwd).is_relative_to(BASE / 'fc'):
                        self.paths[root['sandbox_id']] = cwd
                device = fields.get('path', '')
                if fields.get('message') == 'created or acquired shared read-only ublk device' and re.fullmatch(r'/dev/ublkb\d+', device):
                    self.devices[device] = {'key': fields.get('key'),
                                            'eventTimestamp': row.get('timestamp'),
                                            'dev_id': fields.get('dev_id')}
            except (ValueError, TypeError, AttributeError):
                continue

    def block(self, names=None):
        paths = P('/sys/class/block').glob('ublkb*') if names is None else (
            P('/sys/class/block') / name for name in names
            if re.fullmatch(r'ublkb\d+', name)
        )
        out = {}
        for path in paths:
            try:
                dev = self.read(path / 'dev')
                counters = self.read(path / 'stat')
                if dev is not None and counters is not None:
                    out[path.name] = {'dev': dev.strip(),
                                      'stat': [int(value) for value in counters.split()]}
            except (ValueError, OSError):
                continue
        return out

    def mapped(self, ids, fc):
        out = {}
        by_cwd = {row['cwd']: row for row in fc.values()}
        for sid in ids:
            row = by_cwd.get(self.paths.get(sid))
            if row is None:
                out[sid] = {'available': False, 'reason': 'pool_work_dir_not_in_live_fc_set'}
                continue
            process = P('/proc', str(row['pid']))
            try:
                first = self.read(process / 'stat')
                text = self.read(process / 'maps', 2 * 1024**2)
                last = self.read(process / 'stat')
                if first is None or last is None or text is None or any(
                    procstat(value)['starttime'] != row['starttime'] for value in (first, last)
                ):
                    raise RuntimeError('FC identity changed while reading memory mappings')
                devices = sorted(set(re.findall(r'/dev/ublkb\d+', text)))
                out[sid] = {'available': True, 'pid': row['pid'],
                            'starttime': row['starttime'], 'devices': devices,
                            'deviceKeys': {dev: self.devices.get(dev) for dev in devices}}
            except (ValueError, IndexError, OSError, RuntimeError) as error:
                out[sid] = {'available': False, 'reason': type(error).__name__}
        return out

    def host_snapshot(self):
        vmstat_raw = self.read('/proc/vmstat', 128 * 1024)
        try:
            vmstat = selected_vmstat(vmstat_raw) if vmstat_raw is not None else None
        except ValueError as error:
            self.note('host_vmstat', error)
            vmstat = None
        keys = {'MemAvailable', 'MemFree', 'Cached', 'Buffers', 'Dirty', 'Writeback',
                'SwapTotal', 'SwapFree', 'Active(file)', 'Inactive(file)'}
        memory = {}
        for line in (self.read('/proc/meminfo') or '').splitlines():
            key, _, value = line.partition(':')
            if key in keys:
                memory[key] = value.strip()
        nodes = {}
        for node in sorted(P('/sys/devices/system/node').glob('node[0-9]*'))[:256]:
            raw = self.read(node / 'numastat', 4000)
            if raw is not None:
                nodes[node.name] = raw
        return {
            'scope': 'host-wide; other services may contribute to these counters',
            'vmstat': vmstat, 'psi': {name: self.read('/proc/pressure/' + name)
                                     for name in ('memory', 'io', 'cpu')},
            'meminfo': memory, 'numaNodes': nodes,
            'numaBalancing': self.read('/proc/sys/kernel/numa_balancing'),
            'thpEnabled': self.read('/sys/kernel/mm/transparent_hugepage/enabled'),
            'thpDefrag': self.read('/sys/kernel/mm/transparent_hugepage/defrag'),
            'thpPmdSize': self.read('/sys/kernel/mm/transparent_hugepage/hpage_pmd_size'),
            'pageSize': os.sysconf('SC_PAGE_SIZE'),
        }

    def start_profile(self, group):
        self.group = group
        perf = shutil.which('perf')
        state = self.profile.setdefault(group, {})
        state.update(method='perf-cgroup-host-kernel', event='cpu-clock:kH',
                     frequencyHz=99, callGraph='fp', clock='CLOCK_MONOTONIC',
                     scope='own service cgroup including background pool/daemon work',
                     perfAvailable=bool(perf), status='unavailable')
        if not perf:
            return
        log = None
        try:
            log = (self.directory / (group + '.perf.log')).open('xb')
            args = [perf, 'record', '-a', '-e', 'cpu-clock:kH', '-G',
                    'system.slice/' + UNIT, '-F', '99', '-g', '--call-graph', 'fp',
                    '--clockid', 'mono', '-m', '32', '-B', '-o',
                    str(self.directory / (group + '.perf.data')), '--', 'sleep', '1800']
            environment = dict(os.environ, DEBUGINFOD_URLS='')
            self.perf = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                         start_new_session=True, env=environment)
            self.perf_log = log
            state['recordStartMonotonicNs'] = time.monotonic_ns()
            time.sleep(.25)
            if self.perf.poll() is None:
                state['status'] = 'recording'
            else:
                state.update(status='startup_failed', perfStartupExit=self.perf.returncode)
                self.perf = None
                log.close()
                self.perf_log = None
        except (OSError, subprocess.SubprocessError) as error:
            state.update(status='startup_failed', startupError=type(error).__name__ + ': ' + str(error)[:1000])
            self.perf = None
            self.perf_log = None
            if log is not None:
                log.close()

    def stop_profile(self):
        process, self.perf = self.perf, None
        log, self.perf_log = self.perf_log, None
        if process is None:
            return
        state = self.profile.setdefault(self.group, {})
        state['recordStopRequestedMonotonicNs'] = time.monotonic_ns()
        state['endedBeforeStopRequest'] = process.poll() is not None
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                state['stopEscalated'] = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, getattr(signal, 'SIGKILL', 9))
                    process.wait(timeout=5)
            state['perfExit'] = process.returncode
        except (OSError, subprocess.SubprocessError) as error:
            state.update(status='stop_failed', stopError=type(error).__name__ + ': ' + str(error)[:1000])
            self.note('stop_perf', error)
        finally:
            if log is not None:
                log.close()
        data = self.directory / (self.group + '.perf.data')
        if not data.is_file():
            state.update(status='record_failed', rawPerfAvailable=False)
            return
        try:
            state.update(rawPerfAvailable=True, rawPerfPath=str(data),
                         rawPerfBytes=data.stat().st_size)
            with data.open('rb') as stream:
                state['rawPerfSha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            decoded = self.directory / (self.group + '.kernel-stacks.txt')
            decode_deadline = time.monotonic() + 60
            fields = 'comm,pid,tid,cpu,time,event,ip,sym,dso,period'
            state['decodeFields'] = fields
            state['decodeAttempts'] = []
            for attempt in range(2):
                args = [shutil.which('perf'), 'script', '--ns', '-F', fields, '-i', str(data)]
                if attempt == 0:
                    args.append('--no-inline')
                with decoded.open('xb' if attempt == 0 else 'wb') as stream:
                    completed = subprocess.run(
                        args, stdout=stream, stderr=subprocess.PIPE,
                        timeout=max(.001, decode_deadline - time.monotonic()),
                        env=dict(os.environ, DEBUGINFOD_URLS=''),
                    )
                decode_error = completed.stderr.decode(errors='replace')[-2000:]
                state['decodeAttempts'].append({
                    'noInline': attempt == 0, 'exit': completed.returncode,
                    'error': decode_error,
                })
                unsupported_no_inline = ('no-inline' in decode_error and
                                         any(word in decode_error.lower() for word in
                                             ('unknown option', 'unrecognized option',
                                              'unrecognised option', 'invalid option')))
                if completed.returncode == 0 or attempt == 1 or not unsupported_no_inline:
                    break
                state['noInlineUnsupported'] = True
            state.update(decodeExit=completed.returncode,
                         decodeError=decode_error)
            count = 0
            with decoded.open(errors='replace') as stream:
                for line in stream:
                    if re.search(r'\d+\.\d{9}:.*cpu-clock', line):
                        count += 1
            state['sampleCountDecoded'] = count
            state['lossCountersExplicitlyDecoded'] = False
            if completed.returncode != 0:
                state['status'] = 'decode_failed'
            elif count == 0:
                state['status'] = 'decoded_no_samples'
            elif state.get('status') == 'stop_failed' or state['endedBeforeStopRequest'] or process.returncode not in (0, -signal.SIGINT, 128 + signal.SIGINT):
                state['status'] = 'incomplete'
            else:
                state['status'] = 'complete'
        except subprocess.TimeoutExpired as error:
            state.update(status='decode_timeout', decodeTimeoutSec=60)
            self.note('decode_perf', error)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            state.update(status='decode_failed', decodeError=type(error).__name__ + ': ' + str(error)[:2000])
            self.note('decode_perf', error)

    def snapshot(self, event):
        self.tail()
        fc = self.scan()
        mappings = self.mapped(list(event.get('sandboxIds') or []), fc)
        blocks = self.block()
        full = event['phase'] == 'group' and event['edge'] == 'before'
        changed_fc, fc_present = changed_rows(fc, self.snapshot_last, full)
        changed_blocks, block_present = changed_rows(blocks, self.block_last, full)
        result = {
            'event': event, 'unixNs': time.time_ns(), 'monotonicNs': time.monotonic_ns(),
            'snapshotEncoding': 'full' if full else 'changed rows plus complete presence lists',
            'fc': changed_fc, 'fcPresent': fc_present,
            'threadInventoryChanges': thread_inventory_changes(fc, self.snapshot_last),
            'blockDevices': changed_blocks, 'blockPresent': block_present,
            'fcScanReadInterval': self.last_scan_interval,
            'cgroupCpu': self.read(self.cgroup / 'cpu.stat'), 'mappings': mappings,
            'resident': {}, 'residencyNotMeasured': 'No memory device opener or page touching',
            'clockTicksPerSecond': os.sysconf('SC_CLK_TCK'),
        }
        if event['phase'] == 'group':
            result['host'] = self.host_snapshot()
        self.snapshot_last = fc
        self.block_last = blocks
        return result

    def event(self, path):
        if self.closed:
            raise RuntimeError('Observer already closed')
        path = P(path)
        if path.is_symlink() or path.stat().st_size > 65536 or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}\.json', path.name):
            raise ValueError('Invalid observer event file')
        event = validate_event(json.loads(path.read_text()))
        self.group = event['group']
        self.current_event = event
        if event['phase'] == 'group' and event['edge'] == 'before':
            self.start_profile(self.group)
        value = self.snapshot(event)
        with (self.directory / (path.stem + '.snapshot.json')).open('x') as stream:
            stream.write(json.dumps(value) + '\n')
        if event['phase'] == 'group' and event['edge'] == 'after':
            self.stop_profile()
            self.current_event = None
        return value

    def periodic(self):
        if self.closed or self.current_event is None:
            return
        started = time.monotonic_ns()
        self.tick += 1
        self.tail()
        fc = self.scan(include_threads=False)
        previous = self.sample_last
        mapped_cwds = set(self.paths.values())
        for pid, row in fc.items():
            old = previous.get(pid)
            counters_changed = old is not None and old['starttime'] == row['starttime'] and any(
                row[key] != old[key] for key in ('minflt', 'majflt', 'utime', 'stime')
            )
            if row['state'] == 'R' or counters_changed or row['cwd'] in mapped_cwds:
                row['schedstatSampled'] = True
                row['schedstat'] = self.thread_stats(pid, row['starttime'])
        changed, present = changed_rows(fc, previous)
        thread_changes = thread_inventory_changes(fc, previous)
        self.sample_last = fc
        # Periodic block reads are limited to template memory devices already
        # identified by service logs, rather than a global diskstats scan.
        names = [P(dev).name for dev, row in self.devices.items()
                 if isinstance(row.get('key'), str) and row['key'].endswith('/memory/image.json')]
        blocks = self.block(names)
        block_changes, block_present = changed_rows(blocks, self.sample_block_last)
        self.sample_block_last = blocks
        sample = {
            'unixNs': time.time_ns(), 'monotonicNs': time.monotonic_ns(),
            'event': self.current_event, 'fcChanged': changed, 'fcPresent': present,
            'fcScanReadInterval': self.last_scan_interval,
            'sampleReadInterval': {'startNs': started, 'endNs': time.monotonic_ns(),
                                   'clock': 'CLOCK_MONOTONIC', 'atomic': False},
            'threadSampling': 'all TIDs of mapped, runnable or counter-changing FC; all FC TIDs at boundaries',
            'threadInventoryChanges': thread_changes,
            'trackedBlockStats': block_changes, 'trackedBlockPresent': block_present,
            'blockStatInterpretation': 'Cumulative coarse block counters; not per-I/O latency',
            'cgroupCpu': self.read(self.cgroup / 'cpu.stat'),
        }
        self.samples.write(json.dumps(sample) + '\n')
        self.samples.flush()

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.stop_profile()
        except BaseException as error:
            # Preserve the caller's original experiment exception in finally.
            self.note('close_profile', error)
        for stream in (self.samples, self.stacks):
            try:
                stream.close()
            except BaseException as error:
                self.note('close_stream', error)
        try:
            with (self.directory / 'profile-status.json').open('x') as stream:
                stream.write(json.dumps({'profiles': self.profile, 'observerErrors': self.errors}, indent=2) + '\n')
        except BaseException as error:
            self.note('save_profile_status', error)
