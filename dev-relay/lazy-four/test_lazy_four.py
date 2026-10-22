import base64
import copy
import importlib.util
import io
from pathlib import Path
import struct
import threading
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


t = module('lazy_four_transport')
s = module('lazy_four_snapshots')
r = module('lazy_four_report')


def snapshot():
    a, b = {'digest': 'sha256:' + 'a' * 64, 'size': 65536}, {'digest': 'sha256:' + 'b' * 64, 'size': 65536}
    record = {'id': '0' * 36, 'resources': {'cpu_count': 2, 'memory_mib': 4096},
              'committed': {'rootfs_layers': [{'Managed': a}, {'Managed': b}], 'memory_layers': [a],
                            'runtime_versions':{'tools_drive_version':'0.1.1'}}}
    manifest = {'memory': {'virtualSize': 4096 * 1024**2}}
    return record, manifest


class Contracts(unittest.TestCase):
    def test_capture_tail_and_memory_layer_coverage(self):
        record, manifest = snapshot()
        files, roots = s.snapshot_contract(record, manifest)
        self.assertEqual(len(roots), 2)
        self.assertEqual(set(files), {s.layer_name(x['Managed']) for x in record['committed']['rootfs_layers']})
        c = {'digest': 'sha256:' + 'c' * 64, 'size': 4096}
        record['committed']['memory_layers'].append(c)
        files, _ = s.snapshot_contract(record, manifest)
        self.assertIn(s.layer_name(c), files)

    def test_extra_drives_and_native_snapshots_refused(self):
        record, manifest = snapshot()
        record['committed']['attached_drives'] = ['unhandled']
        with self.assertRaises(RuntimeError):
            s.snapshot_contract(record, manifest)
        record['committed']['attached_drives'] = []
        manifest['nativeRootfs'] = {'version': 1}
        with self.assertRaises(RuntimeError):
            s.snapshot_contract(record, manifest)

    def test_external_lower_never_silently_omitted(self):
        record, manifest = snapshot()
        record['committed']['rootfs_layers'][0] = {'External': {}}
        with self.assertRaises(RuntimeError):
            s.snapshot_contract(record, manifest)

    def test_archive_member_traversal_refused(self):
        record, _ = snapshot()
        templates, files = [], {}
        for i in range(4):
            sid = str(i) * 36
            templates.append({'templateIndex': i, 'templateId': sid, 'rootfsLayers': []})
            files.update({name: {'bytes': 1, 'sha256': 'a' * 64} for name in
                          ['catalog/records/' + sid + '.json'] + ['snapshots/' + sid + '/' + n for n in
                          ('commit', 'vm_state.bin', 'firecracker-manifest.json')]})
        files.update({n: {'bytes': 1, 'sha256': 'a' * 64} for n in ('selection.private.json', 'historical-reference.private.json')})
        value = {'version': 1, 'kind': 'ordinary-four-snapshots', 'templates': templates, 'files': files}
        s.valid_manifest(value)
        value['files']['../escaped'] = {'bytes': 1, 'sha256': 'a' * 64}
        with self.assertRaisesRegex(RuntimeError, 'Unexpected archive path'):
            s.valid_manifest(value)

    def test_metadata_frames_and_truncation(self):
        stream = io.BytesIO()
        t.send(stream, threading.Lock(), 1, b'{"state":"ok"}')
        stream.seek(0)
        self.assertEqual(t.frame(stream), (1, b'{"state":"ok"}'))
        with self.assertRaises(EOFError):
            t.frame(io.BytesIO(b'\0'))
        with self.assertRaises(RuntimeError):
            t.frame(io.BytesIO(t.HEADER.pack(1, 4097)))

    def test_metadata_rpc_multiplex_and_error_no_retry(self):
        incoming, outgoing = io.BytesIO(), io.BytesIO()
        for i in range(1, 9):
            t.send(incoming, threading.Lock(), i, b'{"operation":"status"}')
        incoming.seek(0)
        calls = []
        def request(raw):
            calls.append(raw)
            raise OSError('modeled lost grant')
        t.serve_owner(incoming, outgoing, request)
        outgoing.seek(0)
        replies = dict(t.frame(outgoing) for _ in range(8))
        self.assertEqual(set(replies), set(range(1, 9)))
        self.assertTrue(all(x == b'{"state":"error"}' for x in replies.values()))
        self.assertEqual(len(calls), 8)

    def test_report_preserves_negative_budget_result_and_na_physical_net(self):
        reports = report_fixture()
        result = r.compare(reports)
        self.assertLess(result['rows'][1]['localReductionMinusCoverageModelBytes'], 0)
        self.assertIsNone(result['globalPhysicalNetSavingBytes'])
        self.assertEqual(result['guestsPerRound'], 16)
        self.assertIn('764', r.markdown(result))

    def test_report_refuses_tampered_gate_or_snapshot(self):
        reports = report_fixture()
        reports[-1]['completedSample']['rootfsLowerFiles']['residentBytes'] = 5
        with self.assertRaisesRegex(ValueError, 'Gate does not bind'):
            r.compare(reports)
        reports = report_fixture()
        reports[-1]['ordinaryTemplates'][0]['snapshotEvidence']['committedRecordSha256'] = 'other'
        with self.assertRaisesRegex(ValueError, 'Snapshots, binaries'):
            r.compare(reports)

    def test_report_refuses_mapping_only_acceptance(self):
        reports = report_fixture()
        for report in reports:
            if report['scenario'] == 'lazy':
                report['completedSample']['provider']['counters']['nodeReadRequests'] = 0
        rebind_gates(reports)
        with self.assertRaisesRegex(ValueError, 'No actual lazy broker reads'):
            r.compare(reports)


def rebind_gates(reports):
    for variant in ('off', 'lazy'):
        pair = {x['node']:x for x in reports if x['scenario']==variant}
        for stage in ('admission', 'completed'):
            readies = {node:{'node':node, 'variant':stage, 'epoch':variant+stage, 'runId':row['runId'],
                             'sandboxIds':[j['sandboxId'] for j in row['jobs']]} for node,row in pair.items()}
            measured = {node:{'readySha256':r.digest(readies[node]),'sampleSha256':r.digest(row[stage+'Sample'])} for node,row in pair.items()}
            for node,row in pair.items():
                row[stage+'Gate']={'node':node,'epoch':variant+stage,'status':'COORDINATED_EIGHT_GUEST_GATE_COMPLETED',
                                  'readies':copy.deepcopy(readies),'measurements':copy.deepcopy(measured)}


def report_fixture():
    reports=[]
    for variant in ('off','lazy'):
        for node in ('node-a','node-b'):
            jobs=[]
            for i,count in enumerate((32,57,46,56)):
                for slot in (0,1):
                    jobs.append({'sandboxId':f'{variant}-{node}-{i}-{slot}', 'instanceId':str(i),'slot':slot,
                                 'originalTemplateId':str(i),'replaySha256':str(i),'resources':{'cpu_count':2,'memory_mib':4096},
                                 'stepsCompleted':count,'failedCommands':0,'state':'REPLAY_COMPLETED',
                                 'privateUpperIsolationPassed':True,'replayStartedUnix':1,'replayFinishedUnix':2})
            sample={'startNs':1,'endNs':2,'rootfsLowerFreshSample':True,
                    'rootfsLowerFiles':{'available':True,'residentBytes':100 if variant=='off' else 0},
                    'provider':{'available':True,'enabled':True,'cacheId':'same','pool':{'objectName':'same','mappingBytes':256*1024**2},
                                'sdkReportedBackingCoverageBytes':256*1024**2,
                                'counters':{'nodeReadRequests':5,'nodeReadBytes':256,'fillErrors':0}}}
            binding={'status':'EIGHT_ACTUAL_GUEST_ROOTFS_BINDINGS_VERIFIED','mode':variant,'guests':{j['sandboxId']:{} for j in jobs}}
            reports.append({'scenario':variant,'node':node,'runId':variant+node,
                            'status':'LAZY_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED','workerExitCode':0,
                            'ownedGuestsReleased':True,'outcomeUncertain':False,'jobs':jobs,'binaryPins':{'server':'same'},
                            'ordinaryTemplates':[{'templateIndex':i,'snapshotEvidence':{'snapshotId':str(i),
                                'committedRecordSha256':str(i),'rootfsLayers':[str(i)]}} for i in range(4)],
                            'admissionSample':copy.deepcopy(sample),'completedSample':copy.deepcopy(sample),
                            'rootfsBindingEvidence':binding,'finalRootfsBindingEvidence':copy.deepcopy(binding),
                            'preAdmissionLowerCacheAfter':{'residentBytes':0,'evictionRequested':True},
                            'measurementSummary':{'sampleCount':2}})
    rebind_gates(reports)
    return reports


if __name__ == '__main__':
    unittest.main()
