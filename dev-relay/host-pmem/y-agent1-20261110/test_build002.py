import ast,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
class Compile(unittest.TestCase):
    def setUp(self):self.text=(H/'Y_compile_agent1_002.py').read_text(encoding='utf-8')
    def test_requested_source_not_substituted(self):
        self.assertIn("original=P('/home/jwk/AgentENV')",self.text)
        self.assertIn('COMMIT=head.stdout.strip()',self.text)
        self.assertNotIn('fetch-exact-original-commit',self.text)
        self.assertIn('no alternate source will be fetched',self.text)
    def test_no_patches_or_global_commands(self):
        values=[n.value for n in ast.walk(ast.parse(self.text)) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
        for value in ('dnf','apt-get','modprobe','systemctl','sysctl','apply','curl'):self.assertNotIn(value,values)
        self.assertNotIn('initial-pool.patch',self.text)
    def test_resource_and_source_guards(self):
        for value in ("'--locked','--release','-j','4'",'available<128*2**30',"'--local','--no-hardlinks','--no-checkout'",'Source modified by build'):
            self.assertIn(value,self.text)
    def test_deployment_pending_is_explicit(self):
        self.assertIn("STATE['deployment_pending']=True",self.text)
        self.assertIn("STATE['service_started']=False",self.text)
if __name__=='__main__':unittest.main()
