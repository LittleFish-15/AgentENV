import ast,base64,importlib.util,pathlib,unittest
from urllib.parse import urlsplit
H=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('proxy',H/'auth_proxy010.py');proxy=importlib.util.module_from_spec(spec);spec.loader.exec_module(proxy)
class ProxyTests(unittest.TestCase):
    def test_registry_target_allowed(self):self.assertEqual(proxy.parse_target('CONNECT','ghcr.io:443'),('ghcr.io',443))
    def test_unrelated_target_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'allowlist'):proxy.parse_target('CONNECT','example.org:443')
    def test_suffix_attack_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'allowlist'):proxy.parse_target('CONNECT','github.com.example.org:443')
    def test_url_userinfo_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'userinfo'):proxy.parse_target('CONNECT','someone@github.com:443')
    def test_connect_auth_sent_only_in_upstream_request(self):
        remote=urlsplit('http://example-user:example-pass@proxy.invalid:8080')
        request=proxy.upstream_request(b'CONNECT ghcr.io:443 HTTP/1.1\r\nProxy-Authorization: attacker\r\n\r\n','CONNECT','ghcr.io:443',remote)
        expected=base64.b64encode(b'example-user:example-pass')
        self.assertIn(b'Proxy-Authorization: Basic '+expected+b'\r\n',request);self.assertNotIn(b'attacker',request)
        self.assertTrue(request.startswith(b'CONNECT ghcr.io:443 HTTP/1.1\r\n'))
    def test_http_replaces_client_proxy_auth_and_closes_connection(self):
        remote=urlsplit('http://example-user:example-pass@proxy.invalid:8080')
        request=proxy.upstream_request(b'GET http://ghcr.io/v2/ HTTP/1.1\r\nHost: ghcr.io\r\nProxy-Authorization: attacker\r\nConnection: keep-alive\r\n\r\n','GET','http://ghcr.io/v2/',remote)
        self.assertNotIn(b'attacker',request);self.assertNotIn(b'keep-alive',request)
        self.assertEqual(request.count(b'Proxy-Authorization:'),1);self.assertIn(b'Connection: close\r\n',request)
    def test_generated_probe_sends_real_crlf(self):
        tree=ast.parse((H/'Y_start_runtime010.py').read_text(encoding='utf-8'))
        assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='probe' for x in n.targets))
        program=ast.literal_eval(assignment.value)
        data=next(n.value for n in ast.walk(ast.parse(program)) if isinstance(n,ast.Constant) and isinstance(n.value,bytes) and n.value.startswith(b'CONNECT'))
        self.assertIn(b'\r\n',data);self.assertNotIn(b'\\r\\n',data)
if __name__=='__main__':unittest.main()
