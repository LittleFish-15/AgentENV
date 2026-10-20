"""Fault-injected ownership/cleanup checks; never allocates the 540MiB request."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import types
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('canary_test',HERE/'ub_real_layer_canary.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)

class Canary(unittest.TestCase):
    def fixture(self,mode='ok'):
        events=[];saved=[]
        class Condition:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def wait_for(self,predicate,timeout):return predicate()
        class Backend:
            def __init__(self,library,limit):
                events.append(('backend',limit));self.allocation_calls=0;self.mappings=[]
        class Publisher:
            def __init__(self,backend,journal):
                self.backend=backend;self.state={'objects':[]};events.append('publisher')
            def publish(self,sources,path,budget):
                self.backend.allocation_calls+=1;events.append(('publish',budget,list(sources)))
                self.state['objects']=[{'allocation_attempted':True,'creation_confirmed':mode!='uncertain','delete_acknowledged':False}]
                if mode in ('uncertain','map_failure'):raise RuntimeError(mode)
                replica=types.SimpleNamespace(mappingBytes=T.REQUEST,objectName='own-object',generation='generation',brokerSocket=str(path))
                mapping=types.SimpleNamespace(backing_coverage=640*1024**2);self.backend.mappings.append(mapping)
                return [replica],[mapping]
            def cleanup(self):
                events.append('cleanup')
                if mode=='uncertain':raise RuntimeError('creation unresolved')
                self.state['objects'][0]['delete_acknowledged']=True
        class Broker:
            def __init__(self,*a):self.condition=Condition();self.active=1 if mode=='reader_alive' else 0
            def start(self,*a):events.append('broker-start')
            def stop(self):events.append('broker-stop');return {'read_bytes':T.STORED,'active_leases':0}
        def probe(*a):
            events.append('probe')
            if mode=='bad_hash':raise ValueError('payload mismatch')
        b=types.SimpleNamespace(Publisher=Publisher,Broker=Broker,atomic_json=lambda path,r:saved.append(str(path)))
        s=types.SimpleNamespace(b=b,probe=probe)
        report={'state':'NO_OBJECT_CREATED','allocation_calls_observed':0,'SDK_runtime_started':False}
        with contextlib.redirect_stdout(io.StringIO()):
            T.exercise(s,Path('/source'),Path('/bridge'),Path('/report'),report,Backend)
        return report,events
    def test_success_verifies_payload_then_retires_reader_before_deallocation(self):
        r,e=self.fixture()
        self.assertEqual(r['status'],'ONE_REAL_LARGE_LAYER_PUBLISHED_READ_VERIFIED_AND_RELEASED')
        self.assertEqual(r['allocation_calls_observed'],1);self.assertTrue(r['delete_acknowledged'])
        self.assertLess(e.index('probe'),e.index('broker-stop'));self.assertLess(e.index('broker-stop'),e.index('cleanup'))
        self.assertIn(('publish',T.REQUEST,[T.DIGEST]),e)
    def test_payload_failure_still_releases_known_object_after_reader_exit(self):
        r,e=self.fixture('bad_hash')
        self.assertTrue(r['delete_acknowledged']);self.assertEqual(r['state'],'COMPLETE_NO_OWNED_OBJECT')
        self.assertTrue(r['status'].startswith('STOPPED'))
    def test_map_failure_releases_confirmed_object_without_broker(self):
        r,e=self.fixture('map_failure')
        self.assertIn('cleanup',e);self.assertNotIn('broker-start',e);self.assertTrue(r['delete_acknowledged'])
    def test_uncertain_create_preserved_no_success_or_retry(self):
        r,e=self.fixture('uncertain')
        self.assertEqual(r['allocation_calls_observed'],1)
        self.assertEqual(r['state'],'OWNERSHIP_OR_IMPORT_UNRESOLVED')
        self.assertFalse(r['owned_objects'][0]['delete_acknowledged'])
    def test_live_reader_prevents_unmap_and_delete(self):
        r,e=self.fixture('reader_alive')
        self.assertNotIn('cleanup',e);self.assertEqual(r['state'],'OWNERSHIP_OR_IMPORT_UNRESOLVED')
    def test_pinned_sources_and_mapping_arithmetic(self):
        for name,digest in T.HASHES.items():
            self.assertEqual(hashlib.sha256((HERE.parent/'tools/ub-snapshot'/name).read_bytes()).hexdigest(),digest)
        self.assertEqual(((T.STORED+4096+4*1024**2-1)//(4*1024**2))*(4*1024**2),T.REQUEST)
        self.assertEqual(T.REQUEST,566231040)

if __name__=='__main__':unittest.main(verbosity=2)
