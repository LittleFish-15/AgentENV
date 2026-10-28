from dataclasses import asdict
import copy,socket,struct,types,unittest
from unittest import mock
from aenv_ub_provider import host_dax_worker as w, stored


class WorkerTests(unittest.TestCase):
    def config(self):
        import os
        from pathlib import Path
        sock=str(Path(Path(__file__).anchor)/'broker.sock')
        replica=stored.Replica(sock,'aenv_'+'a'*32,'b'*32,'sha256:'+'c'*64,4096,stored.ALIGN)
        return {'version':1,'uid':1204,'gid':1205,'parentPid':10,'device':123,'socket':sock,
                'files':[{'fd':5,'replica':asdict(replica)}],'payloadResponses':2}

    def worker(self):
        value=w.Worker.__new__(w.Worker)
        value.record={'state':'serving','retireIntent':False};value.save=mock.Mock()
        value.retired=False;value.fds=[];value.control=mock.Mock();value.pin='pin'
        value.process=mock.Mock();value.process.poll.return_value=None
        return value

    def test_contract_rejects_fallback_duplicate_and_control_fd(self):
        good=self.config();self.assertEqual(len(w.validate(good,7)),1)
        for kind in ('fallback','duplicate','control'):
            c=copy.deepcopy(good)
            if kind=='fallback':c['files'][0]['replica']['allowRepositoryFallback']=True
            elif kind=='duplicate':c['files']*=2
            else:c['files'][0]['fd']=7
            with self.subTest(kind=kind),self.assertRaises(ValueError):w.validate(c,7)

    def test_private_control_supports_catalog_over_old_4k_limit(self):
        left,right=socket.socketpair()
        try:
            message={'config':'a'*5000}
            w.send(left,message);self.assertEqual(w.receive(right),message)
            left.sendall(struct.pack('>I',w.MAX_MESSAGE+1))
            with self.assertRaises(ValueError):w.receive(right)
        finally:left.close();right.close()

    def test_busy_reader_does_not_release_parent_fd(self):
        worker=self.worker();worker.request=mock.Mock(return_value={'state':'busy'})
        with self.assertRaises(RuntimeError):worker.retire()
        self.assertFalse(worker.retired);worker.control.close.assert_not_called()

    def test_retirement_waits_for_successful_child_exit(self):
        worker=self.worker();worker.request=mock.Mock(return_value={'state':'released'})
        worker.process.wait.return_value=0
        worker.retire()
        worker.process.wait.assert_called_once_with(timeout=10)
        self.assertTrue(worker.retired)

    def test_unexpected_child_exit_never_implicitly_releases(self):
        worker=self.worker();worker.process.poll.return_value=1
        with self.assertRaises(RuntimeError):worker.retire()
        with self.assertRaises(RuntimeError):worker.reconcile_retirement()
        self.assertFalse(worker.retired);worker.control.close.assert_not_called()

    def test_lost_ack_requires_explicit_successful_exit_reconciliation(self):
        worker=self.worker();worker.process.poll.return_value=0
        with self.assertRaises(RuntimeError):worker.reconcile_retirement()
        worker.record['retireIntent']=True
        worker.reconcile_retirement()
        self.assertTrue(worker.retired);self.assertFalse(worker.record['replyAcknowledged'])

    def test_never_started_child_can_be_explicitly_retired(self):
        worker=self.worker();worker.process=None;worker.record['state']='not_started'
        worker.retire();self.assertTrue(worker.retired)


if __name__=='__main__':unittest.main()
