import importlib.util,json,pathlib,socket,struct,unittest
H=pathlib.Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('packet025',H/'packet025.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def tcp(payload=b'',port=49983,flags=0x18):
 eth=b'\0'*12+struct.pack('!H',0x0800)
 ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40+len(payload),1,0,64,6,0,socket.inet_aton('10.0.0.1'),socket.inet_aton('10.0.0.2'))
 header=struct.pack('!HHIIBBHHH',40000,port,42,7,5<<4,flags,8192,0,0)
 return eth+ip+header+payload
class PacketTests(unittest.TestCase):
 def decode(self,data):return m.decode(data,'aenv-test',4,123,456)
 def test_health_request_no_header_secret(self):
  r=self.decode(tcp(b'GET /health HTTP/1.1\r\nAuthorization: secret-token\r\n\r\n'))
  self.assertEqual(r['httpClass'],'HEALTH_REQUEST');self.assertNotIn('secret-token',json.dumps(r));self.assertNotIn('Authorization',json.dumps(r))
 def test_sdk_api_port_filtered(self):self.assertIsNone(self.decode(tcp(b'GET /health HTTP/1.1\r\nX-API-Key: secret\r\n',port=18080)))
 def test_syn_fields(self):
  r=self.decode(tcp(flags=2));self.assertEqual((r['seq'],r['flags'],r['payloadBytes'],r['kernelUnixNs']),(42,2,0,123))
 def test_arp_request(self):
  frame=b'\0'*12+struct.pack('!H',0x0806)+struct.pack('!HHBBH6s4s6s4s',1,0x0800,6,4,1,b'\x02'*6,socket.inet_aton('10.0.0.1'),b'\0'*6,socket.inet_aton('10.0.0.2'))
  r=self.decode(frame);self.assertEqual((r['protocol'],r['op'],r['dst']),('ARP',1,'10.0.0.2'))
 def test_truncated_ignored(self):self.assertIsNone(self.decode(b'\0'*13))
if __name__=='__main__':unittest.main()
