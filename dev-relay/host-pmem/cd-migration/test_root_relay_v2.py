import ast
import base64
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rootrelay', HERE / 'root_relay_v2.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def setUp(self):
        self.identity = {'machineId':'m','bootId':'b','kernel':'k','hostname':'c'}
        self.job = {'schema':1,'jobId':'root-c-maintenance-001','node':'node-c','sessionId':m.SESSION,
                    'identity':self.identity,'approval':m.APPROVAL,'action':'activate','notBefore':100,'expiresAt':200,
                    'entry':{'repo':'LittleFish-15/AgentENV','path':'dev-relay/host-pmem/cd-migration/C_run_maintenance_v2.py',
                             'commit':'a'*40,'blob':m.DRIVER_BLOB,'sha256':m.DRIVER_SHA,'bytes':m.DRIVER_BYTES}}

    def test_approved_action_and_explicit_restore_only(self):
        m.validate(self.job,self.identity,150)
        m.validate({**self.job,'action':'restore'},self.identity,150)
        for action in ('shell','sh','reboot','allocate','activate; id'):
            with self.assertRaises(RuntimeError):
                m.validate({**self.job,'action':action},self.identity,150)

    def test_queue_cannot_override_script_or_arguments(self):
        for key in ('script','argv','command','env','cwd'):
            with self.assertRaises(RuntimeError):
                m.validate({**self.job,key:'untrusted'},self.identity,150)

    def test_expired_other_machine_and_unapproved_scope(self):
        for changes in ({'expiresAt':149},{'approval':'other'},{'node':'node-d'},
                        {'identity':{**self.identity,'bootId':'new'}}):
            with self.assertRaises(RuntimeError):
                m.validate({**self.job,**changes},self.identity,150)

    def test_unreviewed_driver_path_refused(self):
        for path in ('/bin/sh', 'dev-relay/other.py', 'dev-relay/host-pmem/cd-migration/windows_sftp_bridge_v2.py'):
            changed = {**self.job, 'entry':{**self.job['entry'],'path':path}}
            with self.assertRaises(RuntimeError):
                m.validate(changed,self.identity,150)

    def test_embedded_transport_and_driver_identity(self):
        api = m.api_module()
        self.assertTrue(callable(api.GitHub))
        raw = (HERE / 'C_run_maintenance_v2.py').read_bytes()
        self.assertEqual(len(raw),m.DRIVER_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),m.DRIVER_SHA)
        self.assertEqual(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),m.DRIVER_BLOB)
        ast.parse((HERE / 'root_relay_v2.py').read_bytes(),feature_version=(3,11))


if __name__ == '__main__':
    unittest.main()
