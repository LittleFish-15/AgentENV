"""Zero-capability local TCP/UNIX bridge; no SSH and no credential handling."""
import asyncio
import json
import os
from pathlib import Path
import re
import stat
import sys


async def main():
    assert os.getuid()==os.geteuid()==1204
    assert all(int(l.split()[1],16)==0 for l in Path('/proc/self/status').read_text().splitlines()
               if l.startswith(('CapInh:','CapPrm:','CapEff:','CapAmb:')))
    p=Path(sys.argv[2]);st=p.stat()
    assert p.resolve()==p and st.st_uid==0 and not stat.S_IMODE(st.st_mode)&0o022
    cfg=json.loads(p.read_bytes());inside=sys.argv[1]=='inside'
    assert sys.argv[1] in ('inside','host') and cfg['port']==18231
    assert re.fullmatch('/home/jwk/agent/r/hpab-[ab]-v1/active/api.sock',cfg['socket'])
    async def connect(reader,writer):
        peer=None
        try:
            if inside:r,w=await asyncio.open_connection('127.0.0.1',cfg['port'])
            else:r,w=await asyncio.open_unix_connection(cfg['socket'])
            peer=w
            async def pump(a,b,observe=False):
                first=True
                while True:
                    data=await a.read(65536)
                    if not data:
                        if b.can_write_eof():b.write_eof();await b.drain()
                        break
                    if observe and first:
                        first=False
                        if data.split(b' ',1)[0] not in (b'GET',b'HEAD',b'OPTIONS'):
                            marker=Path(cfg['socket']).parent/'external-mutation-observed'
                            try:
                                fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                                os.write(fd,b'external API mutation observed; backing retirement requires reconciliation\n');os.close(fd)
                            except FileExistsError:pass
                    b.write(data);await b.drain()
            await asyncio.wait_for(asyncio.gather(pump(reader,w,not inside),pump(r,writer)),600)
        except (OSError,asyncio.TimeoutError,ConnectionError):pass
        finally:
            writer.close()
            if peer is not None:peer.close()
    if inside:
        assert not Path(cfg['socket']).exists()
        server=await asyncio.start_unix_server(connect,cfg['socket'])
        os.chmod(cfg['socket'],0o600)
    else:server=await asyncio.start_server(connect,'127.0.0.1',cfg['port'])
    async with server:await server.serve_forever()


if __name__=='__main__':asyncio.run(main())
