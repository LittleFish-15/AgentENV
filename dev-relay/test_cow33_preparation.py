import ast, base64, copy, hashlib, importlib.util, json, re, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name):
    s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
selection=load('cow33_selection');restore=load('cow33_restore_original')
class Preparation(unittest.TestCase):
    def fixture(self):
        cases=[];replays={}
        for lang,count,cmd in [('go',31,'go test ./...; go build; git diff; cat a; sed x'),('ts',15,'npm install; npm test; python3 x'),('java',9,'mvn test; ./gradlew test')]:
            for i in range(count):
                raw=json.dumps({'trajectory':[{'action':cmd},{'action':'submit'}]}).encode();name=lang+str(i)
                cases.append({'instance_id':name+'-1','language':lang,'reference_wall_seconds':200+60*i,
                    'recorded_wait_seconds':150+50*i,'replay_file':name,'replay_sha256':hashlib.sha256(raw).hexdigest()})
                replays[name]=base64.b64encode(raw).decode()
        return {'cohort':{'cases':cases},'replays':replays}
    def test_selection_unique_deterministic_and_balanced(self):
        d=self.fixture();r=selection.select(d);self.assertEqual(r,selection.select(d))
        self.assertEqual(r['batch_sizes'],[17,16]);self.assertEqual(len(r['selected']),33)
        self.assertEqual(len({x['instance_id'] for x in r['selected']}),33)
        for lang,count in [('go',18),('ts',9),('java',6)]:self.assertEqual(sum(c['language']==lang for c in r['selected']),count)
    def test_selection_digest_mismatch_rejected(self):
        d=self.fixture();d['cohort']['cases'][0]['replay_sha256']='0'*64
        with self.assertRaises(ValueError):selection.select(d)
    def test_no_terminal_following_commands_counted(self):
        d=self.fixture();c=d['cohort']['cases'][0];raw=json.dumps({'trajectory':[{'action':'go test'},{'action':'submit'},{'action':'go vet'}]}).encode()
        c['replay_sha256']=hashlib.sha256(raw).hexdigest();d['replays'][c['replay_file']]=base64.b64encode(raw).decode()
        self.assertNotIn('go_vet',selection.features(c,d))
    def test_restore_scope_has_no_module_or_stop_commands(self):
        t=ast.parse(restore.ROOT_SOURCE)
        values=[n.value for n in ast.walk(t) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for forbidden in ('modprobe','rmmod','stop','restart','--force'):self.assertNotIn(forbidden,values)
        self.assertIn('start',values);self.assertIn('/run/cow55-original-unit-recovery-backup.txt',values)
    def test_launcher_allowlist_accepts_exact_approved_layout(self):
        t=ast.parse(restore.ROOT_SOURCE)
        p=next(n.value for n in ast.walk(t) if isinstance(n,ast.Constant) and isinstance(n.value,str) and 'aenv-run-v4-' in n.value)
        self.assertIsNotNone(re.fullmatch(p,'/home/jwk/agent/relay/aenv-run-v4-012abc/deployment.py'))
        for value in ('/tmp/deployment.py','/home/jwk/agent/relay/aenv-run-v4-012abc/deploymentXpy'):
            self.assertIsNone(re.fullmatch(p,value))
    def test_reconstructed_profile_retains_existing_isolation(self):
        for line in ('User=jwk','Group=jwk','SupplementaryGroups=kvm aenv','PrivateNetwork=yes','PrivateMounts=yes',
                     'NoNewPrivileges=yes','CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN','LimitMEMLOCK=2147483648'):
            self.assertIn(line,restore.ROOT_SOURCE)
        self.assertIn("need(before['MainPID']=='0'",restore.ROOT_SOURCE)

if __name__=='__main__':unittest.main()
