import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import uuid

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


rollout, protocol = load('lazy_four_rollout'), load('four_sync')
PASS = 'LAZY_FOUR_REPLAY_COMPLETED_OWNED_GUESTS_RELEASED'


class RolloutTests(unittest.TestCase):

    def pair(self, early=False):
        states, events = {}, []
        class Sync:
            @staticmethod
            def prepare(node, stage, epoch):
                ready = {'node': node, 'variant': stage, 'epoch': epoch, 'runId': ('a' if node == 'node-a' else 'b') * 32,
                         'sandboxIds': [node + '-' + str(i) for i in range(8)]}
                states[node, stage, epoch] = {'ready': ready, 'measured': None, 'failed': None, 'abort': None}
            control_message = staticmethod(protocol.control_message)
            @staticmethod
            def control(node, stage, epoch, op, value=None):
                item = states[node, stage, epoch]
                events.append((node, stage, op))
                if op == 'status':
                    return copy.deepcopy(item)
                if op == 'measure':
                    item['measured'] = {'node': node, 'epoch': epoch, 'readySha256': protocol.digest(item['ready']), 'sampleSha256': 'f' * 64}
                if op == 'release':
                    assert all(states[n, stage, epoch]['measured'] for n in ('node-a', 'node-b'))
                if op == 'abort':
                    item['abort'] = True
                return {'recorded': op}
        def remote(stage, epoch, op, value=None):
            if op == 'prepare':
                Sync.prepare('node-b', stage, epoch); return {'prepared': True}
            return Sync.control('node-b', stage, epoch, op, value)
        class Future:
            def __init__(self, index): self.index = index
            def done(self): return early and self.index == 0
            def result(self): return {'status': PASS, 'workerExitCode': 0} if self.index == 0 else (None, 0)
        class Pool:
            def __init__(self, **kw): self.n = 0
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, *args):
                value = Future(self.n); self.n += 1; return value
        class Steps:
            def call(self, *args): pass
        with mock.patch.multiple(rollout, sync_module=lambda: Sync, remote_pair=remote,
                                 save=lambda *args: None, fetch_b=lambda name: json.dumps({'status': PASS, 'workerExitCode': 0})), \
             mock.patch.object(rollout.concurrent.futures, 'ThreadPoolExecutor', Pool), \
             mock.patch.object(rollout.time, 'sleep', lambda value: None):
            if early:
                with self.assertRaises(RuntimeError): rollout.run_dual(Steps(),'off')
            else:
                rollout.run_dual(Steps(),'off')
        return events

    def test_both_eight_guest_gates_finish_before_dual_return(self):
        events = self.pair()
        self.assertEqual(sum(op == 'release' for _, _, op in events), 4)
        self.assertFalse(any(op == 'abort' for _, _, op in events))

    def test_early_worker_end_aborts_both_stages_on_both_nodes(self):
        events = self.pair(True)
        self.assertEqual(sum(op == 'abort' for _, _, op in events), 4)
        self.assertFalse(any(op == 'release' for _, _, op in events))


if __name__ == '__main__':
    unittest.main()
