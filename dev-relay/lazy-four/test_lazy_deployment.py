import ast
import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent


def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


service=module('prepare_lazy_four_service')
root=module('lazy_four_root')
runtime=module('four_runtime')
provider=module('lazy_four_provider')
rollout=module('lazy_four_rollout')
cohort=module('lazy_four_cohort')


class DeploymentContracts(unittest.TestCase):
    def test_isolated_namespace_and_same_binary_receipt(self):
        for node in ('node-a','node-b'):
            service.select_node(node)
            self.assertEqual(service.D,root.D)
            self.assertEqual(str(service.UNIT),'jwk-aenv-lazy-four-32ce41c-'+node+'.service')
            self.assertIn('r/lazy-four-',service.RUNTIME.as_posix())
            self.assertIn('r/fc-lazy-four-',service.FC_WORK.as_posix())
        self.assertEqual(service.COMMIT,rollout.CORE)
        self.assertEqual(service.CORE_TREE,rollout.CORE_TREE)
        self.assertNotEqual(provider.PROVIDER_CORE,service.COMMIT)

    def test_snapshot_tools_and_no_prewarm(self):
        config=service.configuration('0.1.1')
        self.assertIn('version = "0.1.1"',config)
        self.assertNotIn('startup_prewarm = true',config)
        self.assertIn('[pool.firecracker]\nenabled = false',config)
        with self.assertRaises(RuntimeError):service.configuration('0.1.1-native')

    def test_environment_modes_never_enable_native_or_memory(self):
        source=(HERE/'prepare_lazy_four_service.py').read_text(encoding='utf-8')
        tree=ast.parse(source)
        make=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='make_module')
        env=next(n for n in make.body if isinstance(n,ast.FunctionDef) and n.name=='environment')
        definition={}
        scope={'definition':definition,'original_environment':lambda:{'AENV_DIRECT_ROOTFS_BINDING':'bad',
               'AENV_UB_MEMORY_REPLICAS':'bad','AENV_UB_ROOTFS_REPLICAS':'bad','KEEP':'ok'},
               'need':service.need,'digest':lambda raw:'verified','own':lambda *args:b'fixture'}
        exec(compile(ast.Module(body=[env],type_ignores=[]),'<actual-env>','exec'),scope)
        self.assertEqual(scope['environment'](),{'KEEP':'ok'})
        definition['lazyActivation']=('/exact/index','verified')
        self.assertEqual(scope['environment'](),{'KEEP':'ok','AENV_UB_ROOTFS_REPLICAS':'/exact/index'})
        definition['lazyActivation']=('/exact/index','wrong')
        with self.assertRaises(RuntimeError):scope['environment']()

    def test_root_command_is_enum_not_shell(self):
        self.assertEqual(root.validate_request({'nonce':'n','sequence':1,'operation':'observe'},'n',1),'observe')
        for request in ({'nonce':'n','sequence':1,'operation':'rm -rf /'},
                        {'nonce':'n','sequence':1,'operation':'runtime-off','command':'anything'},
                        {'nonce':'wrong','sequence':1,'operation':'runtime-off'}):
            with self.assertRaises(RuntimeError):root.validate_request(request,'n',1)

    def test_provider_start_and_finish_refuse_live_baseline(self):
        supervisor=root.Supervisor.__new__(root.Supervisor)
        supervisor.off_stopped=False
        supervisor.runtime_identity=['loaded','active',123,'456']
        supervisor.provider_started=False
        supervisor.check_old=lambda:None
        with self.assertRaisesRegex(RuntimeError,'baseline fully stops'):
            supervisor.start_provider()
        with self.assertRaisesRegex(RuntimeError,'Stop own Runtime'):
            supervisor.execute('finish')

    def test_root_observation_pins_are_exact_sources(self):
        source=(HERE/'lazy_four_root.py').read_text(encoding='utf-8')
        tree=ast.parse(source)
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Supervisor')
        observe=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='observe')
        text=ast.get_source_segment(source,observe)
        self.assertIn("self.scope['pins'][str(path)]",text)
        self.assertIn("body.get('metadata',{}).get('cow_batch')==case['runId']",text)
        self.assertNotIn("'POST'",text)
        self.assertNotIn("'DELETE'",text)

    def test_actual_lower_binding_requires_complete_exact_index(self):
        layer={'digest':'sha256:'+'a'*64,'size':4096}
        ref={'layerDigest':layer['digest'],'fileBytes':4096,'allowRepositoryFallback':False,'brokerSocket':'/own/data.sock'}
        config={'lowers':[{**layer,'ub':ref}]}
        self.assertTrue(runtime.binding_contract(config,[layer],'lazy',{'replicas':[ref]}))
        with self.assertRaises(RuntimeError):runtime.binding_contract(config,[layer],'off',None)
        with self.assertRaises(RuntimeError):runtime.binding_contract(config,[layer,layer],'lazy',{'replicas':[ref]})
        config['lowers'][0]['ub']={**ref,'allowRepositoryFallback':True}
        with self.assertRaises(RuntimeError):runtime.binding_contract(config,[layer],'lazy',{'replicas':[ref]})

    def test_all_helpers_and_nested_pins_match(self):
        for name,pin in rollout.PUBLIC_PINS.items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),pin,name)
        for name,pin in cohort.PINS.items():
            self.assertEqual(hashlib.sha256((HERE/(name+'.py')).read_bytes()).hexdigest(),pin,name)
        self.assertEqual(runtime.ROOT_CLIENT_SHA,hashlib.sha256((HERE/'lazy_four_root_client.py').read_bytes()).hexdigest())

    def test_rollback_source_uses_exact_new_namespace(self):
        raw=base64.b64decode(service.CONTROL_SOURCE_B64)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),service.CONTROL_SOURCE_SHA)
        self.assertIn(b'agentenv-lazy-four-32ce41c',raw)
        self.assertNotIn(b'6cdac56',raw)
        ast.parse(raw)

    def test_readonly_ram_geometry_is_four_gib(self):
        raw=(HERE/'ram_observer.py').read_text(encoding='utf-8')
        self.assertIn('parse_guest_smaps(smaps, backend, 4096 * 1024**2',raw)
        self.assertNotIn('parse_guest_smaps(smaps, backend, 512 *',raw)

    def test_provider_sdk_lock_surrounds_serve_and_pool_fixed_before_run(self):
        raw=(HERE/'lazy_four_provider.py').read_text(encoding='utf-8')
        tree=ast.parse(raw)
        serve=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='serve')
        body=ast.get_source_segment(raw,serve)
        self.assertLess(body.index('fcntl.flock'),body.index('service.serve'))
        self.assertIn('finally:os.close(lock)',body)
        self.assertIn("'poolBytes':256*MIB",raw)
        self.assertIn("'coverageGuardBytes':512*MIB",raw)


if __name__=='__main__':unittest.main()
