"""Socket-activated, capability-free proxy with private systemd credentials."""
import asyncio,base64,json,os,pathlib,socket,ssl,struct
from urllib.parse import unquote,urlsplit
ALLOWED=('github.com','githubusercontent.com','ghcr.io','docker.io','docker.com','amazonaws.com','cloudfront.net',
 'myhuaweicloud.com','huaweicloud.com','quay.io','gcr.io','pkg.dev','googleapis.com')
def require(ok,message):
    if not ok:raise RuntimeError(message)
def parse_target(method,target):
    parsed=urlsplit('//'+target if method=='CONNECT' else target)
    host=parsed.hostname or '';port=parsed.port or (443 if method=='CONNECT' or parsed.scheme=='https' else 80)
    require(parsed.username is None and parsed.password is None,'URL userinfo is not allowed')
    require(any(host==s or host.endswith('.'+s) for s in ALLOWED) and port in (80,443),'Destination is outside registry allowlist')
    if method!='CONNECT':require(parsed.scheme=='http','Expected HTTP proxy URL')
    return host,port
def proxy_authorization(proxy):
    if proxy.username is None:return b''
    value=unquote(proxy.username)+':'+unquote(proxy.password or '')
    return b'Proxy-Authorization: Basic '+base64.b64encode(value.encode())+b'\r\n'
def upstream_request(header,method,target,remote):
    host,port=parse_target(method,target);authority=host+':'+str(port)
    if method=='CONNECT':
        return b'CONNECT '+authority.encode()+b' HTTP/1.1\r\nHost: '+authority.encode()+b'\r\n'+proxy_authorization(remote)+b'\r\n'
    lines=header.split(b'\r\n');kept=[line for line in lines[1:] if line and line.split(b':',1)[0].lower() not in
      (b'proxy-authorization',b'proxy-connection',b'connection')]
    return lines[0]+b'\r\n'+b''.join(line+b'\r\n' for line in kept)+proxy_authorization(remote)+b'Connection: close\r\n\r\n'
async def main():
    require(os.geteuid() not in (0,1002),'Proxy must use its separate DynamicUser')
    require(int(os.environ.get('LISTEN_PID','0'))==os.getpid() and os.environ.get('LISTEN_FDS')=='1','Missing systemd socket activation')
    credentials=pathlib.Path(os.environ['CREDENTIALS_DIRECTORY'])
    config=json.loads((credentials/'upstream.json').read_text())
    require(config['client_uid']==1002,'Unexpected peer UID binding')
    async def accept(reader,writer):
        other_writer=None;phase='peer'
        try:
            raw=writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            require(struct.unpack('3i',raw)[1]==config['client_uid'],'Unexpected peer')
            phase='request';header=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),30);require(len(header)<65536,'Oversized request')
            method,target,_=header.split(b'\r\n',1)[0].decode('ascii').split(' ',2);host,port=parse_target(method,target)
            value=config.get('https' if method=='CONNECT' else 'http') or config.get('https') or config.get('http')
            require(value,'Upstream proxy is not configured');remote=urlsplit(value)
            require(remote.scheme in ('http','https') and remote.hostname,'Unsupported upstream proxy')
            context=ssl.create_default_context(cafile=str(credentials/'ca.pem')) if remote.scheme=='https' else None
            phase='connect';other_reader,other_writer=await asyncio.wait_for(asyncio.open_connection(remote.hostname,remote.port or (443 if context else 80),ssl=context),30)
            other_writer.write(upstream_request(header,method,target,remote));await other_writer.drain()
            if method=='CONNECT':
                phase='proxy-auth';response=await asyncio.wait_for(other_reader.readuntil(b'\r\n\r\n'),30)
                require(response.split(b'\r\n',1)[0].split()[1]==b'200','Proxy tunnel was rejected')
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');await writer.drain()
            phase='relay'
            async def pump(source,dest):
                while data:=await source.read(65536):dest.write(data);await dest.drain()
                if dest.can_write_eof():dest.write_eof()
            await asyncio.wait_for(asyncio.gather(pump(reader,other_writer),pump(other_reader,writer)),7200)
        except Exception as error:
            # Never log request headers, proxy URLs, credentials or exception text.
            print(json.dumps({'phase':phase,'errorType':type(error).__name__}),flush=True)
        finally:
            writer.close()
            if other_writer:other_writer.close()
    listener=socket.socket(fileno=3);listener.setblocking(False)
    server=await asyncio.start_unix_server(accept,sock=listener)
    print('AUTH_PROXY_READY_WITH_PRIVATE_SYSTEMD_CREDENTIALS',flush=True)
    async with server:await server.serve_forever()
if __name__=='__main__':asyncio.run(main())
