"""Ordinary-user bounded mailbox client for the fixed root supervisor."""
import json
import os
from pathlib import Path
import stat
import time
import uuid

WORK=Path('/home/jwk/agent/r/lazy-four-rollout-v1')
OPS=('runtime-off','runtime-stop','provider-start','runtime-lazy','observe','finish')


def need(ok,message):
    if not ok:raise RuntimeError(message)


def read(path,owner):
    need(path.resolve(strict=True)==path and path.is_relative_to(WORK),'Unexpected root mailbox path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        m=os.fstat(fd)
        need(stat.S_ISREG(m.st_mode) and m.st_uid==owner and m.st_nlink in (1,2) and m.st_size<=1024**2,'Unexpected mailbox file')
        return json.load(stream)


def request(operation):
    import fcntl
    need(os.getuid()==os.geteuid()==1204 and operation in OPS,'Use ordinary jwk and a fixed operation')
    mailbox=WORK/'root-mailbox';need(mailbox.resolve(strict=True)==mailbox and mailbox.stat().st_uid==1204,'Unexpected mailbox')
    fd=os.open(mailbox/'channel.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_uid==1204 and meta.st_nlink==1,'Unexpected channel mutex')
        fcntl.flock(fd,fcntl.LOCK_EX)
        scope=read(WORK/'root-scope.json',1204)
        ready=read(mailbox/'ready.json',0);need(ready['nonce']==scope['nonce'],'Root session differs')
        state_path=mailbox/'client-state.json'
        previous=read(state_path,1204) if state_path.exists() else {'completed':0}
        need(set(previous)=={'completed'} and type(previous['completed']) is int and 0<=previous['completed']<10000,'Prior root request unresolved')
        sequence=previous['completed']+1
        path=mailbox/f'{sequence:04d}.request.json'
        need(not path.exists(),'Root request already exists; outcome must be reconciled, never resent')
        def atomic(path,value):
            tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
            with tmp.open('x') as out:json.dump(value,out);out.flush();os.fsync(out.fileno())
            os.replace(tmp,path)
        atomic(path,{'nonce':scope['nonce'],'sequence':sequence,'operation':operation})
        target=mailbox/f'{sequence:04d}.reply.json';deadline=time.monotonic()+240
        while not target.exists():
            need(time.monotonic()<deadline,'Root request remains pending; preserve mailbox')
            time.sleep(.05 if operation=='observe' else .5)
        value=read(target,0)
        need(value.get('status')=='ROOT_OPERATION_COMPLETED' and value.get('sequence')==sequence
             and value.get('nonce')==scope['nonce'] and value.get('operation')==operation,
             'Root operation failed; preserve mailbox: '+str(value.get('reason','inspect root terminal')))
        atomic(state_path,{'completed':sequence})
        return value
    finally:os.close(fd)
