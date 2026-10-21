"""Resample retained lower-file residency; never create Guests or alter services.

Historical sandbox references are preserved, not claimed to be live references.
No payload reads, hashes, cache eviction, device mapping or privileged collection.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time

ROOT = Path('/home/jwk/agent')
REPOSITORY = ROOT / 'deployments/agentenv-ae9c626-baseline/state/snapshot-store/repository/managed-layers'
RUN = '083604f2f76045c0beb8de4cf92c0758'


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def read(path, limit=64 * 1024**2):
    path = Path(path)
    need(path.resolve(strict=True) == path, 'Redirected input: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'Oversized input')
    return raw


def references(frame, jobs):
    """Reject a truncated sweep even if the old collector called it complete."""
    expected = {(j['template_id'], j['sandbox_id']) for j in jobs}
    if not frame.get('complete_reference_inventory') or frame.get('errors'):
        return None
    files = {f['file_id']: f for f in frame['files']}
    by_pair = {}
    counts = {}
    for ref in frame['references']:
        if ref['kind'] != 'rootfs_lower':
            continue
        key = (ref['template_id'], ref['sandbox_id'])
        need(key in expected and ref['file_id'] in files, 'Unbound historical reference')
        by_pair.setdefault(key, set()).add(ref['file_id'])
        counts[key] = counts.get(key, 0) + 1
    if set(by_pair) != expected:
        return None
    need(all(counts[k] == len(v) for k, v in by_pair.items()), 'Repeated lower reference; layer count ambiguous')
    return files, by_pair


def resident(path, expected, page):
    """mincore as the inode owner, without dereferencing the mapped contents."""
    path = Path(path)
    need(path.parent == REPOSITORY and path.resolve(strict=True) == path, 'Lower outside original managed repository')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid(), 'mincore requires the actual file owner')
        need((before.st_dev, before.st_ino, before.st_size) ==
             (expected['device'], expected['inode'], expected['file_bytes']), 'Historical lower identity/size changed')
        need(0 < before.st_size <= 64 * 1024**3, 'Lower size outside bound')
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
        libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        cached = 0
        for offset in range(0, before.st_size, 256 * 1024**2):
            length = min(256 * 1024**2, before.st_size - offset)
            address = libc.mmap(None, length, 1, 1, fd, offset)
            need(address not in (None, ctypes.c_void_p(-1).value), 'Read-only mmap failed')
            try:
                bits = (ctypes.c_ubyte * ((length + page - 1) // page))()
                need(libc.mincore(address, length, bits) == 0, 'mincore failed')
                cached += sum(bool(bit & 1) for bit in bits)
            finally:
                need(libc.munmap(address, length) == 0, 'munmap failed')
        after = os.fstat(fd)
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(stamp(before) == stamp(after), 'Lower changed during measurement')
        return {'available': True, 'resident_bytes': cached * page,
                'file_bytes': before.st_size, 'allocated_bytes': before.st_blocks * 512,
                'page_span_bytes': ((before.st_size + page - 1) // page) * page,
                'owner_uid': before.st_uid, 'owner_authorized_mincore': True}
    finally:
        os.close(fd)


def totals(ids, samples, field):
    values = [samples[i].get(field) for i in ids]
    return sum(values) if all(v is not None for v in values) else None


def fraction(a, b):
    return a / b if a is not None and b else None


def summarize(files, pairs, samples):
    rows = []
    tids = sorted({t for t, _ in pairs})
    for tid in tids:
        keys = sorted(k for k in pairs if k[0] == tid)
        need(len(keys) == 2, 'Expected two historical sandboxes per template')
        a, b = (pairs[k] for k in keys)
        common, union = a & b, a | b
        row = {'template_id': tid, 'historical_sandbox_ids': [k[1] for k in keys],
               'sandbox1_lower_layer_count': len(a), 'sandbox2_lower_layer_count': len(b),
               'common_lower_layer_count': len(common), 'same_lower_set': a == b}
        for prefix, ids in [('sandbox1_lower', a), ('sandbox2_lower', b), ('common_lower', common), ('unique_lower', union)]:
            for field in ('file_bytes', 'allocated_bytes', 'page_span_bytes', 'resident_bytes'):
                row[prefix + '_' + field] = totals(ids, samples, field)
        c = row['common_lower_resident_bytes']
        row['common_lower_residency_fraction'] = fraction(c, row['common_lower_page_span_bytes'])
        row['common_fraction_of_referenced_lower_cache'] = fraction(c, row['unique_lower_resident_bytes'])
        r1, r2 = row['sandbox1_lower_resident_bytes'], row['sandbox2_lower_resident_bytes']
        row['independent_lower_cache_copy_model_saving_fraction'] = fraction(c, r1 + r2 if r1 is not None and r2 is not None else None)
        row['current_upper_bytes'] = None
        row['current_lower_plus_upper_cache_shared_fraction'] = None
        row['actual_two_sandbox_accessed_page_intersection_bytes'] = None
        rows.append(row)
    ids = set().union(*pairs.values())
    return {'templates': rows, 'global_unique_lower_file_count': len(ids),
            **{'global_unique_lower_' + f: totals(ids, samples, f) for f in
               ('file_bytes', 'allocated_bytes', 'page_span_bytes', 'resident_bytes')},
            'complete': all(samples[i].get('available') for i in ids)}


def markdown(supplement):
    def mib(v):
        return 'NA' if v is None else f'{v / 1024**2:.3f}'
    def span(tid, field, percentage=False):
        values = [r[field] for s in supplement['samples'] for r in s['templates']
                  if r['template_id'] == tid and r.get(field) is not None]
        if not values:
            return 'NA'
        scale = 100 if percentage else 1 / 1024**2
        return f'{min(values)*scale:.3f}–{max(values)*scale:.3f}' + ('%' if percentage else '')
    lines = ['\n\n# 当前共同 lower 文件的 host pagecache 补采', '',
             '这是原版第一批17模板的历史引用文件在补采时的驻留量。未重跑轨迹、未启动沙箱；不是原运行时刻的新采样，也不是两个沙箱实际读过页面的交集。',
             '历史结果保留于上文。不得将历史 upper、RSS/PSS 与本次驻留量相加计算同一时刻共享比例。容量单位 MiB。',
             '补采时间（UTC）：' + supplement['started_utc'] + ' 至 ' + supplement['finished_utc'], '',
             '|轨迹|模板ID|S1/S2 lower层数|共同层数|共同lower文件大小|当前共同lower驻留|驻留率|共同缓存/引用lower缓存并集|独立缓存副本模型避免率|有效采样|',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in supplement['samples'][0]['templates']:
        tid = r['template_id']
        count = sum(next(x for x in s['templates'] if x['template_id'] == tid)['common_lower_resident_bytes'] is not None for s in supplement['samples'])
        lines.append('|' + '|'.join([supplement['trajectory_by_template'][tid], tid,
            str(r['sandbox1_lower_layer_count']) + '/' + str(r['sandbox2_lower_layer_count']), str(r['common_lower_layer_count']),
            mib(r['common_lower_file_bytes']), span(tid, 'common_lower_resident_bytes'),
            span(tid, 'common_lower_residency_fraction', True), span(tid, 'common_fraction_of_referenced_lower_cache', True),
            span(tid, 'independent_lower_cache_copy_model_saving_fraction', True), str(count)]) + '|')
    lines += ['', '全局按同一节点、boot、设备号、inode去重；不是把各模板行直接相加：', '',
              '|采样|唯一lower文件数|lower文件大小|lower页跨度|lower驻留量|完整|', '|---|---:|---:|---:|---:|---|']
    for i, s in enumerate(supplement['samples']):
        lines.append('|' + '|'.join([str(i), str(s['global_unique_lower_file_count']),
            mib(s['global_unique_lower_file_bytes']), mib(s['global_unique_lower_page_span_bytes']),
            mib(s['global_unique_lower_resident_bytes']), str(s['complete'])]) + '|')
    lines += ['', '计算口径：', '',
        '- 驻留率 = 当前共同 lower 驻留页字节数 / 共同 lower 文件按页向上取整的跨度。尾页取整不应使比例超过100%。',
        '- 共同缓存占比 = 共同 lower 驻留量 / 两个历史沙箱所引用 lower 文件并集的当前驻留量；两侧引用相同集合时可为100%，不代表实际读过全部页面。',
        '- 独立缓存副本模型避免率 = 共同 lower 驻留量 /（S1 lower驻留引用量＋S2 lower驻留引用量）。同集合时为50%；是模型比较，不是测得的整机内存节省率。',
        '- lower文件大小和缓存包含OverlayBD提交格式的索引/头等字节，不能当作纯Guest文件有效数据量。',
        '- upper已随历史沙箱清理，本次不补为0；包含upper的当前共享比例为NA。历史运行期的完整比例仍见原数据。',
        '- 同一文件只采一次后复用引用。普通文件所有者执行mincore，未读取映射内容、未哈希全文件、未清缓存。结果不是原子快照。',
        '- 普通页缓存可能受先前构建/校验或其他进程影响；不做访问归因。完整缺项与逐文件错误见JSON。', '']
    return '\n'.join(lines)


def correct_historical_global(summary, text, valid_ids):
    """Exclude interrupted old sweeps from cohort totals, preserving evidence."""
    excluded = []
    for batch in summary['global_file_cache_sweeps_by_batch']:
        need(batch['batch_number'] == 1, 'Unexpected historical batch')
        keep = []
        for row in batch['sweeps']:
            if str(row['sample_id']) in valid_ids:
                keep.append(row)
            else:
                excluded.append(row)
        batch['sweeps'] = keep
    summary['historical_global_cache_correction'] = {
        'reason': 'Original stop-interrupted sweeps could report complete despite missing template references; validated against raw cache.jsonl',
        'excluded_sweeps': excluded, 'per_template_and_process_rows_unchanged': True}
    marker = '## 每批观测文件去重后的宿主机统计（完整采样窗口）'
    need(text.count(marker) == 1, 'Historical Markdown section differs')
    prefix, old_tail = text.split(marker, 1)
    fields = ('global_rootfs_lower_file_bytes', 'global_rootfs_lower_allocated_bytes', 'global_rootfs_lower_resident_bytes',
              'global_rootfs_upper_allocated_bytes', 'global_rootfs_upper_resident_bytes', 'global_memory_lower_resident_bytes')
    lines = [marker, '', '已核对原始引用清单，剔除缺少模板的中断采样；保留的历史全局范围如下（MiB）。历史 root mincore 权限判据未单独留证，当前补采以实际文件所有者身份复核。', '',
             '|批次|rootfs lower文件|rootfs lower分配|rootfs lower缓存|rootfs upper分配|rootfs upper缓存|memory lower缓存|',
             '|---|---:|---:|---:|---:|---:|---:|']
    for b in summary['global_file_cache_sweeps_by_batch']:
        cols = []
        for f in fields:
            values = [r[f] for r in b['sweeps'] if r.get(f) is not None]
            cols.append(f'{min(values)/1024**2:.3f}–{max(values)/1024**2:.3f}' if values else 'NA')
        lines.append('|1|' + '|'.join(cols) + '|')
    lines += ['', '剔除的原始全局行保存在JSON historical_global_cache_correction.excluded_sweeps；原始输入文件未修改。', '']
    lines += [line for line in old_tail.splitlines() if line.startswith('批次 ')]
    return prefix + '\n'.join(lines)


def main():
    need(os.name == 'posix' and os.uname().nodename == 'server1' and os.getuid() == os.geteuid() == 1204, 'Run as ordinary A/jwk')
    os.umask(0o077)
    pending = json.loads(read(ROOT / 'relay/cow33-batch1-node-a.pending.json'))
    need(pending['run_id'] == RUN and pending.get('all_cohort_guests_released') and not pending.get('restore_outcome_uncertain'), 'First batch cleanup not confirmed')
    need(len(pending['jobs']) == 34 and len({j['template_id'] for j in pending['jobs']}) == 17, 'First batch identity inventory differs')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(boot == pending['scope']['boot_id'], 'Boot changed; historical inode continuity cannot be assumed')
    source = Path(pending['report_directory'])
    need(source.parent == ROOT / 'relay/reports' and source.name.startswith('node-a-cow33-batch1-'), 'Unexpected report scope')
    original_raw = read(source / 'combined-summary.json')
    original = json.loads(original_raw)
    need(len(original['batches']) == 1 and original['batches'][0]['run_id'] == RUN, 'Summary identity differs')
    original_md = read(source / 'combined-summary.md').decode('utf-8')
    cache_path = source / 'measurements/cache.jsonl'
    need(cache_path.resolve(strict=True) == cache_path and cache_path.stat().st_size <= 256 * 1024**2, 'Unexpected cache evidence')
    selected = None
    selected_frame = None
    valid_ids = set()
    with cache_path.open(encoding='utf-8') as stream:
        for line in stream:
            need(len(line) <= 4 * 1024**2, 'Oversized cache record')
            frame = json.loads(line)
            value = references(frame, pending['jobs'])
            if value:
                valid_ids.add(str(frame['sample_id']))
                if selected is None:
                    selected, selected_frame = value, frame
    need(selected is not None, 'No complete historical reference inventory')
    files, pairs = selected
    ids = set().union(*pairs.values())
    need(len(ids) <= 1024, 'File budget exceeded')
    identities = [(files[i]['device'], files[i]['inode']) for i in ids]
    need(len(set(identities)) == len(ids), 'Historical physical identity duplicated')
    need(all(files[i]['boot_id'] == boot for i in ids), 'File identity from different boot')
    page = os.sysconf('SC_PAGESIZE')
    supplemental = {'revision': 'lower-cache-supplement-v1', 'historical_run_id': RUN,
        'scope': 'Current retained rootfs lower residency using historical two-sandbox references',
        'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'page_bytes': page, 'boot_id': boot,
        'trajectory_by_template': {j['template_id']: j['instance_id'] for j in pending['jobs']},
        'source_summary_sha256': hashlib.sha256(original_raw).hexdigest(),
        'historical_reference_sample_id': selected_frame['sample_id'], 'historical_reference_time': selected_frame['started_unix'],
        'new_guest_created': False, 'trajectories_rerun': False, 'services_modified': False,
        'SDK_called': False, 'root_required': False, 'layer_payload_read': False,
        'current_upper_sampled': False, 'actual_access_intersection_measured': False, 'samples': []}
    for index in range(3):
        print('PHASE=lower_cache_sample index=' + str(index), flush=True)
        start = time.time()
        observations = {}
        for i in sorted(ids):
            try:
                observations[i] = resident(files[i]['path'], files[i], page)
            except (OSError, RuntimeError) as error:
                observations[i] = {'available': False, 'error_type': type(error).__name__, 'reason': str(error)}
        result = summarize(files, pairs, observations)
        result.update(started_unix=start, finished_unix=time.time(), files=observations)
        supplemental['samples'].append(result)
        if index < 2:
            time.sleep(1)
    supplemental['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    supplemental['historical_lower_files'] = {i: files[i] for i in sorted(ids)}
    complete = all(s['complete'] for s in supplemental['samples'])
    # Preserve every original field and raw source file; append a separate time window.
    need('current_lower_cache_supplement' not in original, 'Summary already supplemented')
    original_md = correct_historical_global(original, original_md, valid_ids)
    original['current_lower_cache_supplement'] = supplemental
    output = Path(tempfile.mkdtemp(prefix='node-a-lower-cache-supplement-', dir=ROOT / 'relay/reports'))
    (output / 'combined-summary.json').write_text(json.dumps(original, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (output / 'combined-summary.md').write_text(original_md + markdown(supplemental), encoding='utf-8')
    report = {'status': 'LOWER_CACHE_SUPPLEMENT_COMPLETE' if complete else 'LOWER_CACHE_SUPPLEMENT_WITH_GAPS',
        'report_directory': str(output), 'template_count': 17, 'samples': 3,
        'new_guest_created': False, 'compiled': False, 'services_modified': False,
        'historical_source_files_modified': False, 'measurement_time_scope': supplemental['scope'],
        'json': str(output / 'combined-summary.json'), 'markdown': str(output / 'combined-summary.md'),
        'global_samples': [{k: v for k, v in s.items() if k.startswith('global_') or k == 'complete'} for s in supplemental['samples']],
        'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()}}
    print('BEGIN_RETURN_REPORT')
    print(json.dumps(report, indent=2))
    print('END_RETURN_REPORT')
    return 0 if complete else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError) as error:
        print('BEGIN_RETURN_REPORT')
        print(json.dumps({'status': 'STOPPED_LOWER_CACHE_SUPPLEMENT', 'error_type': type(error).__name__, 'reason': str(error)}, indent=2))
        print('END_RETURN_REPORT')
        raise SystemExit(1)
