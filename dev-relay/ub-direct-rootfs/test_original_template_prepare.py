import ast,copy,hashlib,importlib.util,json,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('prep',HERE/'prepare_original_measurement_template.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def fixture():
    layers=[{'digest':'sha256:'+('%064x'%i),'size':4096} for i in range(1,10)]
    resources={'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536}
    template={'templateId':'t','resources':resources,'rootfsLayers':layers[:8]}
    record={'id':'t','resources':resources,'committed':{'rootfs_layers':[{'Managed':x} for x in layers[:8]],'memory_layers':layers[8:]}}
    manifest={'memory':{'virtualSize':4096*1024**2}}
    files={'managed-layers/'+x['digest'].replace(':','_')+'.overlaybd.commit':{'bytes':4096,'sha256':x['digest'][7:]} for x in layers}
    for name in ('catalog/records/t.json','snapshots/t/vm_state.bin','snapshots/t/firecracker-manifest.json','snapshots/t/commit'):
        files[name]={'bytes':100,'sha256':'a'*64}
    return record,manifest,files,template

class Contract(unittest.TestCase):
    def test_exact_first_template_dependency_closure(self):
        names=m.prep_contract(*fixture());self.assertEqual(len(names),13)
        self.assertEqual(sum(n.startswith('managed-layers/') for n in names),9)
    def test_disk_resource_mismatch_rejected(self):
        r,f,files,t=fixture();r=copy.deepcopy(r);r['resources']['disk_size_mib']=1024
        with self.assertRaises(RuntimeError):m.prep_contract(r,f,files,t)
    def test_changed_frozen_lower_hash_rejected(self):
        r,f,files,t=fixture();files[next(iter(files))]['sha256']='f'*64
        with self.assertRaises(RuntimeError):m.prep_contract(r,f,files,t)
    def test_extra_dependency_cannot_be_ignored(self):
        for key in ('attached_drives','volume_snapshots','memory_startup'):
            r,f,files,t=fixture();r['committed'][key]=[{}]
            with self.assertRaises(RuntimeError):m.prep_contract(r,f,files,t)
    def test_missing_vmstate_rejected(self):
        r,f,files,t=fixture();del files['snapshots/t/vm_state.bin']
        with self.assertRaises(KeyError):m.prep_contract(r,f,files,t)
    def test_catalog_is_published_after_dependencies_and_commit(self):
        source=(HERE/'prepare_original_measurement_template.py').read_text()
        tree=ast.parse(source)
        call=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='order')
        names=list(m.prep_contract(*fixture()))
        order=eval(compile(ast.Expression(call.value),'<actual-publication-order>','eval'),{'missing':names})
        self.assertEqual(order[-1],'catalog/records/t.json');self.assertEqual(order[-2],'snapshots/t/commit')
    def test_payload_direct_read_has_no_buffered_fallback(self):
        meta=types.SimpleNamespace(st_dev=1,st_ino=2,st_size=4096,st_mtime_ns=3,st_ctime_ns=4)
        calls=[]
        def failed(path,flags):calls.append(flags);raise OSError('O_DIRECT unsupported')
        with patch.object(m,'prep_meta',return_value=meta),patch.object(m.os,'O_DIRECT',0x4000,create=True),\
             patch.object(m.os,'O_CLOEXEC',0,create=True),patch.object(m.os,'O_NOFOLLOW',0,create=True),\
             patch.object(m.os,'O_NONBLOCK',0,create=True),patch.object(m.os,'preadv',create=True),patch.object(m.os,'open',side_effect=failed):
            with self.assertRaisesRegex(OSError,'unsupported'):m.prep_digest(Path('/source'),True)
        self.assertEqual(len(calls),1);self.assertTrue(calls[0]&0x4000)
    def test_no_data_copy_or_overwrite_primitive(self):
        tree=ast.parse((HERE/'prepare_original_measurement_template.py').read_text())
        attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertIn('link',attrs)
        self.assertFalse({'copy','copyfile','copy2','unlink','remove','rmtree'}.intersection(attrs))
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='replace'
                             and isinstance(n.func.value,ast.Name) and n.func.value.id=='os' for n in ast.walk(tree)))
        self.assertNotIn('write_bytes',attrs)

if __name__=='__main__':unittest.main()
