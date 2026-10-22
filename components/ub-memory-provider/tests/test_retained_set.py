"""Multiple snapshot bindings share one native generation; no SDK calls."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aenv_ub_provider import raw, retained, service
import test_retained_publication as fixtures


class RetainedSetTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RetainedPublicationTests('test_default_plan_verifies_bytes_without_writing_or_opening_sdk')
        self.fixture.setUp()
        self.root = self.fixture.root

    def tearDown(self):
        self.fixture.tearDown()

    def manifests(self, count=4, shared=False, conflict=False):
        entries=[]
        for index in range(count):
            directory=self.root/('s'+str(index));directory.mkdir(mode=0o777)
            (directory/'native-pmem').mkdir(mode=0o777)
            data=bytes([17 if shared else 17+index])*(2*1024**2)
            digest='sha256:'+hashlib.sha256(data).hexdigest()
            (directory/'native-pmem'/('00-'+digest[7:]+'.img')).write_bytes(data)
            manifest=directory/'manifest.json'
            manifest.write_text(json.dumps({'nativeRootfs':{'version':1,'archiveVersion':1,
                'sourceImage':'sha256:'+format(0 if conflict else index,'064x'),'filesystem':'ext4',
                'layers':[{'sha256':digest,'bytes':len(data)}]}}))
            entries.append({'manifest':str(manifest),'artifactRoot':str(directory)})
        path=self.root/'set.json';path.write_text(json.dumps({'version':1,'snapshots':entries}))
        return path,entries

    def args(self,budget=16*1024**2):
        f=self.fixture
        return f.runtime,f.out,f.adapter,f.adapter_sha,'test',budget,128*1024**2

    def published(self,plan,mutate=None):
        value={'version':1,'ownerId':'d'*32,'mode':'pmem','readers':['peer'],
               'replicas':[raw.shape(e['backing'],'aenv_'+format(i,'032x')) for i,e in enumerate(plan['catalog']['objects'])]}
        if mutate:mutate(value)
        path=self.root/'published-set.json';path.write_text(json.dumps(value))
        return path,service.identity_bytes(path)

    def test_four_source_bindings_in_one_generation_and_import_reorders_by_content(self):
        selection,entries=self.manifests()
        plan=retained.plan_publish_set(selection,*self.args(),['peer'])
        self.assertEqual(len(plan['binding']['bindings']),4);self.assertEqual(len(plan['catalog']['objects']),4)
        self.assertEqual(plan['alignedLogicalBytes'],16*1024**2);self.assertFalse(self.fixture.out.exists())
        published,pin=self.published(plan,lambda value:value['replicas'].reverse())
        imports=self.root/'import-set.json';imports.write_text(json.dumps({'version':1,'snapshots':[{'manifest':e['manifest']} for e in entries]}))
        imported=retained.plan_import_set(imports,published,pin,'peer',*self.args())
        self.assertEqual([b['sourceImage'] for b in imported['binding']['bindings']],[b['sourceImage'] for b in plan['binding']['bindings']])
        for a,b in zip(plan['binding']['bindings'],imported['binding']['bindings']):
            self.assertEqual(a['layers'],b['layers']);self.assertNotIn('snapshotSources',b)

    def test_equal_base_content_counts_once_across_distinct_sources(self):
        selection,_=self.manifests(shared=True)
        plan=retained.plan_publish_set(selection,*self.args(4*1024**2),['peer'])
        self.assertEqual(len(plan['binding']['bindings']),4)
        self.assertEqual(len(plan['catalog']['objects']),1);self.assertEqual(plan['alignedLogicalBytes'],4*1024**2)

    def test_conflicting_source_or_combined_budget_is_rejected_without_writes(self):
        selection,_=self.manifests(count=2,conflict=True)
        with self.assertRaisesRegex(ValueError,'conflicting'):retained.plan_publish_set(selection,*self.args(),['peer'])
        value=json.loads(selection.read_text());native=Path(value['snapshots'][1]['manifest'])
        data=json.loads(native.read_text());data['nativeRootfs']['sourceImage']='sha256:'+'f'*64;native.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'Combined'):retained.plan_publish_set(selection,*self.args(4*1024**2),['peer'])
        self.assertFalse(self.fixture.out.exists())

    def test_missing_or_duplicate_import_contents_are_rejected(self):
        selection,entries=self.manifests(count=2)
        plan=retained.plan_publish_set(selection,*self.args(),['peer'])
        imports=self.root/'import-set.json';imports.write_text(json.dumps({'version':1,'snapshots':[{'manifest':e['manifest']} for e in entries]}))
        path,pin=self.published(plan,lambda value:value['replicas'].pop())
        with self.assertRaisesRegex(ValueError,'missing'):retained.plan_import_set(imports,path,pin,'peer',*self.args())
        path,pin=self.published(plan,lambda value:value['replicas'].append(value['replicas'][0]))
        with self.assertRaisesRegex(ValueError,'Duplicate'):retained.plan_import_set(imports,path,pin,'peer',*self.args())

    def test_cli_set_default_is_readonly_and_uses_one_plan(self):
        selection,_=self.manifests(count=2);runtime=self.root/'runtime.json';runtime.write_text(json.dumps(self.fixture.runtime))
        args=['provider','publish-retained-set','--snapshot-set',str(selection),'--device-runtime',str(runtime),
              '--output',str(self.fixture.out),'--adapter',str(self.fixture.adapter),'--adapter-sha256',self.fixture.adapter_sha,
              '--region','test','--max-bytes',str(16*1024**2),'--coverage-bytes',str(128*1024**2),'--reader','peer']
        with patch.object(sys,'argv',args),patch.object(retained,'execute') as execute,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(service.main(),0);execute.assert_not_called()
        self.assertFalse(self.fixture.out.exists())


if __name__=='__main__':unittest.main()
