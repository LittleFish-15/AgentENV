import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock
import urllib.error

spec=importlib.util.spec_from_file_location('download_entry',Path(__file__).with_name('lazy_four_rollout.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
PATH='dev-relay/lazy-four/fixture.py'
RAW=b'print("public fixture")\n'
PIN=hashlib.sha256(RAW).hexdigest()


class Response(io.BytesIO):
    status=200


class Downloads(unittest.TestCase):
    def test_api_content_recovers_from_raw_domain_dependency(self):
        envelope={'type':'file','path':PATH,'encoding':'base64','size':len(RAW),'content':base64.b64encode(RAW).decode()+'\n'}
        client=mock.Mock();client.open.return_value=Response(json.dumps(envelope).encode())
        with mock.patch.object(m.urllib.request,'build_opener',return_value=client):
            self.assertEqual(m.fetch_public(PATH,'a'*40,PIN),RAW)
        self.assertTrue(client.open.call_args.args[0].full_url.startswith('https://api.github.com/'))
        self.assertEqual(client.open.call_count,1)

    def test_api_network_failure_falls_back_to_pinned_raw(self):
        client=mock.Mock();client.open.side_effect=[urllib.error.URLError('modeled proxy tunnel 504'),Response(RAW)]
        with mock.patch.object(m.urllib.request,'build_opener',return_value=client):
            self.assertEqual(m.fetch_public(PATH,'a'*40,PIN),RAW)
        self.assertEqual(client.open.call_count,2)

    def test_checksum_mismatch_never_installs_or_falls_back(self):
        envelope={'type':'file','path':PATH,'encoding':'base64','size':3,'content':base64.b64encode(b'bad').decode()}
        client=mock.Mock();client.open.return_value=Response(json.dumps(envelope).encode())
        with mock.patch.object(m.urllib.request,'build_opener',return_value=client):
            with self.assertRaisesRegex(RuntimeError,'checksum differs'):
                m.fetch_public(PATH,'a'*40,PIN)
        self.assertEqual(client.open.call_count,1)

    def test_failures_have_bounded_retries_and_redacted_messages(self):
        client=mock.Mock();client.open.side_effect=urllib.error.URLError('sensitive-proxy-detail')
        with mock.patch.object(m.urllib.request,'build_opener',return_value=client),mock.patch.object(m.time,'sleep'),mock.patch('builtins.print'):
            with self.assertRaises(RuntimeError) as caught:m.fetch_public(PATH,'a'*40,PIN)
        self.assertEqual(client.open.call_count,4)
        self.assertNotIn('sensitive-proxy-detail',str(caught.exception))

    def test_missing_helpers_are_written_only_after_validation(self):
        with (mock.patch.object(m,'PUBLIC_PINS',{'fixture.py':PIN}),mock.patch.object(m,'HELPERS',Path('/nonexistent-download-test')),
             mock.patch.object(m,'fetch_public',side_effect=RuntimeError('network failure')),mock.patch.object(m,'install_bytes') as write):
            with self.assertRaises(RuntimeError):m.download()
            write.assert_not_called()


if __name__=='__main__':unittest.main()
