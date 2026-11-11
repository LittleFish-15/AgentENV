import ast,hashlib,json,pathlib,tempfile,unittest
H=pathlib.Path(__file__).resolve().parent
tree=ast.parse((H/'wikidata015_worker.py').read_text(encoding='utf-8'))
function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='pinned_image')
code=compile(ast.Module(body=[function],type_ignores=[]),'<image-pin>','exec')
class ImageTests(unittest.TestCase):
    def run_image(self,arch='amd64',index=False,bad_digest=False):
        config=json.dumps({'architecture':arch,'os':'linux'}).encode();csha='sha256:'+hashlib.sha256(config).hexdigest()
        raw=json.dumps({'config':{'digest':csha},'layers':[]}).encode();sha='sha256:'+hashlib.sha256(raw).hexdigest()
        first=json.dumps({'manifests':[{'platform':{'architecture':'amd64','os':'linux'},'digest':'sha256:'+'0'*64 if bad_digest else sha}]}).encode() if index else raw
        with tempfile.TemporaryDirectory(dir=H) as folder:
            def registry(path,accept=None):return (config if '/blobs/' in path else first if path.endswith('/tag') else raw),{}
            scope={'REG':'registry.example','REPO':'group/image','TAG':'tag','registry':registry,'json':json,'hashlib':hashlib,'WORK':pathlib.Path(folder)}
            exec(code,scope);return scope['pinned_image']()
    def test_native_manifest_pinned(self):self.assertEqual(self.run_image()[1]['architecture'],'amd64')
    def test_native_index_selected(self):self.assertIn('@sha256:',self.run_image(index=True)[0])
    def test_wrong_architecture_rejected(self):
        with self.assertRaises(AssertionError):self.run_image(arch='arm64')
    def test_digest_mismatch_rejected(self):
        with self.assertRaises(AssertionError):self.run_image(index=True,bad_digest=True)
if __name__=='__main__':unittest.main()
