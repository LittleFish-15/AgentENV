"""One explicit B import attempt after a verified pre-exec STDOUT failure.

Keeps the failed unit and all evidence. Uses a new SDK unit with journal output;
the B view also logs to the journal. Existing A owner and module state stay.
Use this entry for B release/restore after the controlled continuation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

CONTINUE_PATH=Path('/var/tmp/host-pmem-continue.0TiXa9')
CONTINUE_SHA='60f2831b06f55ef0a20dcbd5eea1ba17e382b778e9c8e9442b032f660336be34'
OLD_UNIT='aenv-hpmem-v2-node-b-sdk.service'
NEW_UNIT='aenv-hpmem-v2-node-b-sdk-journal.service'
VIEW_UNIT='aenv-hpmem-v2-node-b-view.service'
BASE=Path('/var/lib/agentenv-hpmem-demo-v2/node-b')


def need(value,reason):
    if not value:raise RuntimeError(reason)


def read_root(path,limit):
    need(path.resolve(strict=True)==path,'Redirected root artifact')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
             and 0<info.st_size<=limit,'Unexpected root artifact ownership/type/size')
        return stream.read(limit+1)


def preexec_stdout(properties,invocation):
    required={'LoadState':'loaded','ActiveState':'failed','SubState':'failed','MainPID':'0',
              'Result':'exit-code','ExecMainCode':'1','ExecMainStatus':'209','InvocationID':invocation}
    need(all(properties.get(key)==value for key,value in required.items()),
         'Not the exact completed 209/STDOUT failure; no restart')
    need(properties.get('Job','') in ('','0'),'A job is still pending')


def journal_arguments(argv):
    names={'--unit='+NEW_UNIT,'--unit='+VIEW_UNIT}
    if Path(argv[0]).name=='systemd-run' and names.intersection(argv):
        return ['--property=StandardOutput=journal' if value.startswith('--property=StandardOutput=')
                else '--property=StandardError=journal' if value.startswith('--property=StandardError=')
                else value for value in argv]
    return argv


def install(m,inspection,invocation,resume):
    old_ops=m.Operations;old_flow=m.workflow.Workflow;old_command=m.command
    def command(argv,*args,**kwargs):
        adjusted=journal_arguments(argv)
        check=kwargs.pop('check',True)
        result=old_command(adjusted,*args,check=False,**kwargs)
        if check:
            need(result.returncode==0,'Command exit='+str(result.returncode)+' '+str(adjusted[:3])
                 +' stderr='+result.stderr[-1500:]+' stdout='+result.stdout[-1500:])
        return result
    m.command=command

    class Operations(old_ops):
        def __init__(self,node,state):
            super().__init__(node,state)
            if node=='node-b' and state.get('sdkUnitOverride')==NEW_UNIT:self.sdk_unit=NEW_UNIT

        def verify_preexec_failure(self):
            need(inspection is not None,'Missing root inspection')
            need(inspection.get('node')=='node-b' and inspection.get('phase')=='sdk_start_intent'
                 and inspection.get('workflowEpoch')==self.state['epoch']
                 and inspection.get('bootId')==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'Inspection epoch/boot differs')
            preexec_stdout(inspection['unit']['properties'],invocation)
            keys='LoadState,ActiveState,SubState,MainPID,Result,ExecMainCode,ExecMainStatus,InvocationID,Job'
            current=m.command([m.maintenance.tool('systemctl'),'show',OLD_UNIT,'--property='+keys])
            properties=dict(line.split('=',1) for line in current.stdout.splitlines() if '=' in line)
            preexec_stdout(properties,invocation)
            need(not (self.prep/'provider').exists() and not (self.prep/'provider').is_symlink(),
                 'Provider transaction exists; pre-exec retry is not applicable')
            need(m.unit(NEW_UNIT)['LoadState']=='not-found' and m.unit(VIEW_UNIT)['LoadState']=='not-found'
                 and not (self.work/'view').exists(),'Existing retry or view state; preserve it')
            return properties

    class Workflow(old_flow):
        def start(self,peer_token):
            need(resume and self.state['node']=='node-b' and self.state['phase']=='sdk_start_intent'
                 and 'owner' not in self.state and not self.state.get('stdoutRecoveryAttempted')
                 and not self.state.get('viewLaunchAttempted') and peer_token is None,
                 'Only the exact unexecuted B startup may continue once')
            failure=self.ops.verify_preexec_failure()
            peer=self.peer(m.workflow.encode(self.state['peerEvidence']),'publisher_ready')
            need(peer['peerModuleDigest']==m.workflow.digest(self.state['moduleReady']),
                 'Publisher does not bind this B epoch')
            publication=peer['publication']
            need(peer['publicationIdentity']==m.workflow.manifest_identity(publication),'Publication changed')
            self.ops.check_candidate()
            self.mark('sdk_start_intent',stdoutRecoveryAttempted=True,sdkUnitOverride=NEW_UNIT,
                      previousSdkUnitFailure=failure,auxiliaryOutputMode='journal')
            self.ops.sdk_unit=NEW_UNIT
            owner=self.ops.start_sdk(publication)
            need(owner['publication']==publication,'Imported publication differs')
            self.mark('sdk_serving',owner=owner)
            self.mark('view_start_intent')
            view=self.ops.start_view(owner)
            self.mark('view_serving',view=view)
            sample=self.ops.measure()
            token=self.envelope('reader_ready',publicationDigest=m.workflow.digest(publication),
                                peerEpoch=peer['epoch'],sample=sample)
            self.mark('data_ready',dataReady=token,sample=sample)
            return m.workflow.encode(token)
    m.Operations=Operations;m.workflow.Workflow=Workflow


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('resume-sdk','release','restore','status','report'))
    parser.add_argument('--inspection');parser.add_argument('--failed-invocation')
    parser.add_argument('--peer-token');parser.add_argument('--approval')
    args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and os.uname().nodename=='agent1','Expected B root')
    inspection=None
    if args.mode=='resume-sdk':
        need(args.inspection and args.failed_invocation,'Explicit inspected failure required')
        path=Path(args.inspection)
        need(path.is_absolute() and path.is_relative_to(BASE),'Inspection must stay within this root transaction')
        inspection=json.loads(read_root(path,1024**2))
        preexec_stdout(inspection['unit']['properties'],args.failed_invocation)
        workflow=read_root(BASE/'workflow.json',1024**2)
        need(hashlib.sha256(workflow).hexdigest()==inspection['workflowSha256'],'State changed since inspection')
    raw=read_root(CONTINUE_PATH,11659)
    need(len(raw)==11659 and hashlib.sha256(raw).hexdigest()==CONTINUE_SHA,'Retained continuation differs')
    previous=types.ModuleType('verified_existing_continuation');previous.__file__=str(CONTINUE_PATH)
    exec(compile(raw,str(CONTINUE_PATH),'exec'),previous.__dict__)
    old_configure=previous.configure
    def configure(m):
        old_configure(m)
        install(m,inspection,args.failed_invocation,args.mode=='resume-sdk')
    previous.configure=configure
    sys.argv=[str(CONTINUE_PATH),'start' if args.mode=='resume-sdk' else args.mode]
    if args.approval:sys.argv+=['--approval',args.approval]
    if args.peer_token:sys.argv+=['--peer-token',args.peer_token]
    return previous.main()


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'HOST_PMEM_B_JOURNAL_CONTINUATION_STOPPED','reason':str(error),
                          'automaticRetry':False,'moduleChanges':False}))
        raise SystemExit(1)
