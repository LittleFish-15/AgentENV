"""Assemble a private four-template report without re-running any experiment."""
import hashlib, json, os, stat


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def report(scope):
    rt = scope['module']('four_runtime')
    analysis = scope['module']('dsec_report')
    work = scope['WORK']
    source = rt.load(work / 'single-a/report.json')
    state = rt.load(work / 'single-a/state.json')
    need(source.get('coreCommit') == scope['CORE'] and source.get('context') == state.get('context') and
         source.get('runId') == state.get('runId'), 'Replay report/state identity differs')
    sample_path = work / 'root-observations.jsonl'
    need(sample_path.resolve(strict=True) == sample_path, 'Redirected observer log')
    fd = os.open(sample_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    samples = []
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 1204 and before.st_size <= 512 * 1024**2,
             'Observer log ownership/size differs')
        digest = hashlib.sha256()
        for line in stream:
            need(len(line) <= 2 * 1024**2 and line.endswith(b'\n'), 'Observer log incomplete/oversized line')
            digest.update(line)
            value = json.loads(line)
            if value.get('runId') == source['runId']:
                samples.append(value)
        after = os.fstat(stream.fileno())
    need((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
         'Observer still writing; preserve log and run report after observation ends')
    observer_end = rt.load(work / 'observer-return.json')
    plan = rt.load(work / 'observer-plan.json')
    need(all(s.get('observerRunId') == plan['observerRunId'] for s in samples), 'Observer run differs')
    jobs = source.get('jobs', [])
    events = {}
    for job in jobs:
        path = work / 'single-a/commands' / (str(job['index']) + '-events.jsonl')
        rows = [json.loads(line) for line in rt.read(path, 8 * 1024**2).splitlines()] if path.exists() else []
        events[(job['instanceId'], job['slot'])] = rows
    result = {'revision': 'dsec-four-report-v1', 'status': source['status'], 'coreCommit': scope['CORE'],
              'runId': source['runId'], 'context': source['context'], 'jobs': jobs,
              'ownedGuestsReleased': source.get('ownedGuestsReleased'), 'observer': observer_end,
              'samplesSha256': digest.hexdigest(), 'sampleFile': str(sample_path),
              'SDK_called': False, 'measurementSummary': analysis.summarize(samples, jobs),
              'referenceRequiredForComparison': True,
              'replayComparison': {'sameReplayOutcomesAccepted': False, 'historicalReferenceOnly': True,
                  'reasons': ['Reference per-command outcomes are not included in this delivery; compare returned private artifacts locally']},
              'commandOutcomes': [{'instanceId': key[0], 'slot': key[1], 'events': value} for key, value in events.items()],
              'rawObservations': samples,
              'rootfsActualAccessResidentIntersectionBytes': None, 'globalPhysicalSavingBytes': None,
              'memfileCrossNodePrivateCowAccepted': False, 'rootfsCrossNodePhysicalSharingAccepted': False}
    rt.save(work / 'comparison-input.private.json', result)
    text = analysis.markdown(result)
    # Uses the same bounded atomic writer (JSON) for the source of truth. The
    # Markdown is derived and contains no API credentials or command text.
    target = work / 'measurement-report.md'
    need(not target.is_symlink(), 'Redirected Markdown output')
    with target.open('w', encoding='utf-8') as stream:
        stream.write(text)
    print(json.dumps({'status': 'DSEC_PRIVATE_REPORT_WRITTEN', 'input': str(work / 'comparison-input.private.json'),
                      'markdown': str(target), 'sameWorkloadAccepted': False, 'physicalNetSavingBytes': None}))
    return 0
