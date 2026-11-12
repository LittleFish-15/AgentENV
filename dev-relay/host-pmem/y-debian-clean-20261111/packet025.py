"""Receive-only own-netns ARP/envd TCP metadata; never persist packet payloads."""
import json,os,pathlib,select,socket,struct,time
def decode(data,interface,packet_type,timestamp_ns,receive_ns):
 if len(data)<14:return None
 kind=struct.unpack_from('!H',data,12)[0];offset=14
 for _ in range(2):
  if kind not in (0x8100,0x88a8):break
  if len(data)<offset+4:return None
  kind=struct.unpack_from('!H',data,offset+2)[0];offset+=4
 row={'kernelUnixNs':timestamp_ns,'receiveUnixNs':receive_ns,'interface':interface,'packetType':packet_type}
 if kind==0x0806:
  if len(data)<offset+28:return None
  ht,pt,hl,pl,op,sm,si,tm,ti=struct.unpack_from('!HHBBH6s4s6s4s',data,offset)
  if (ht,pt,hl,pl)!=(1,0x0800,6,4):return None
  row.update(protocol='ARP',op=op,src=socket.inet_ntoa(si),dst=socket.inet_ntoa(ti),srcMac=sm.hex(':'),dstMac=tm.hex(':'));return row
 if kind!=0x0800 or len(data)<offset+20:return None
 ihl=(data[offset]&15)*4;total=struct.unpack_from('!H',data,offset+2)[0]
 if ihl<20 or data[offset+9]!=6 or len(data)<offset+ihl+20:return None
 tcp=offset+ihl;sport,dport,seq,ack=struct.unpack_from('!HHII',data,tcp)
 if 49983 not in (sport,dport):return None
 thl=(data[tcp+12]>>4)*4
 if thl<20:return None
 flags=data[tcp+13];payload_len=max(0,total-ihl-thl);prefix=data[tcp+thl:tcp+thl+40]
 label=None
 if prefix.startswith(b'GET /health HTTP/'):label='HEALTH_REQUEST'
 elif prefix.startswith(b'POST /init HTTP/'):label='INIT_REQUEST'
 elif prefix.startswith(b'HTTP/'):
  words=prefix.split(b' ',2)
  if len(words)>1 and len(words[1])==3 and words[1].isdigit():label='HTTP_STATUS_'+words[1].decode('ascii')
 row.update(protocol='TCP',src=socket.inet_ntoa(data[offset+12:offset+16]),dst=socket.inet_ntoa(data[offset+16:offset+20]),sport=sport,dport=dport,seq=seq,ack=ack,flags=flags,payloadBytes=payload_len,httpClass=label)
 return row
def main():
 base=pathlib.Path('/home/jwk/aenv-y-clean-20261111/diagnostic025');assert os.getuid()==os.geteuid()==1002
 values={a:int(b.strip(),16) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line for a,b in [line.split(':',1)] if a.startswith('Cap')}
 assert all(values[n]==1<<13 for n in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')),'Capture needs only CAP_NET_RAW'
 sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024**2)
 sock.setsockopt(socket.SOL_SOCKET,35,1);sock.setblocking(False)
 ready={'uid':1002,'caps':values,'netns':os.stat('/proc/self/ns/net').st_ino,'kernelTimestamps':True,'receiveBuffer':sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),'payloadStored':False}
 with (base/'capture-ready.json').open('x') as f:json.dump(ready,f)
 count=0;deadline=time.monotonic()+180;reason='stop_file';timestamps_missing=0
 try:
  with (base/'packet-metadata.jsonl').open('x') as log:
   while not (base/'capture-stop').exists():
    if time.monotonic()>deadline:reason='duration_limit';break
    if count>=60000:reason='record_limit';break
    if not select.select([sock],[],[],.1)[0]:continue
    data,ancillary,flags,address=sock.recvmsg(65535,128);now=time.time_ns();stamp=None
    for level,kind,raw in ancillary:
     if level==socket.SOL_SOCKET and kind==35 and len(raw)>=16:
      sec,nsec=struct.unpack_from('qq',raw);stamp=sec*10**9+nsec
    row=decode(data,address[0],address[2],stamp,now)
    if row is None:continue
    if stamp is None:timestamps_missing+=1
    log.write(json.dumps(row,separators=(',',':'))+'\n');count+=1
  stats=sock.getsockopt(263,6,12);packets,drops=struct.unpack_from('II',stats)
  with (base/'capture-result.json').open('x') as f:json.dump({**ready,'records':count,'socketPackets':packets,'socketDrops':drops,'missingKernelTimestamps':timestamps_missing,'stopReason':reason},f)
 finally:sock.close()
if __name__=='__main__':main()
