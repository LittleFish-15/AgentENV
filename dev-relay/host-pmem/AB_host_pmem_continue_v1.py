"""Continue the current two-node experiment with corrected srcversion validation.

Keeps the original experiment epochs and the running A SDK owner. Stages a new
root-owned code directory; never edits code used by an existing process. A's
resume-view operation cannot allocate or restart SDK. Use this continuation
for later B start, retirement and recovery as well.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import types
import zlib

FIX_CORE='782577411ff20522d33c22dffb533e9678334fed'
OLD_CORE='5562478d1883215ed1f81786fa316ac593259119'
OLD_ENTRY_SHA='f36685e3d56746b9c8e588d42a49108660283f6b93dcb399302e2cae023b91a5'
NEW_PACKAGE_SHA='d4227d1781428ab720c157eea6a7588ab74284918d2cbe0f165f190e0eef15df'
OLD_CLI_SHA='05315ed699215d2afc5d5235517e51aca5daf55212d5bb55326bfb3fa342e6ad'
NEW_CLI_SHA='e0aa999df4da339882916ee37cfd459f887bc407e1de7fc3981047a900d1890a'
FIXED_CLI='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'
ENTRIES={'server1':'/var/tmp/host-pmem-v2.K6IOW9','agent1':'/var/tmp/host-pmem-v2.7UH9sz'}


def need(value,reason):
    if not value:raise RuntimeError(reason)


def configure(m):
    old=json.loads(zlib.decompress(base64.b64decode(m.PACKAGE)))
    need(m.CORE_COMMIT==OLD_CORE,'Unexpected frozen experiment revision')
    need(hashlib.sha256(old['host_pmem_cli.py'].encode()).hexdigest()==OLD_CLI_SHA,'Old CLI source differs')
    corrected=zlib.decompress(base64.b64decode(FIXED_CLI)).decode()
    need(hashlib.sha256(corrected.encode()).hexdigest()==NEW_CLI_SHA,'Corrected CLI source differs')
    old['host_pmem_cli.py']=corrected
    raw=json.dumps(old,separators=(',',':'),ensure_ascii=False).encode()
    need(hashlib.sha256(raw).hexdigest()==NEW_PACKAGE_SHA,'Patched package differs')
    m.PACKAGE=base64.b64encode(zlib.compress(raw,9)).decode();m.PACKAGE_SHA=NEW_PACKAGE_SHA
    original_ops=m.Operations;original_flow=m.workflow.Workflow;original_report=m.report

    class Operations(original_ops):
        def save(self,value):
            value['codeProvenance']={'experimentCoreCommit':OLD_CORE,'activeCoreCommit':FIX_CORE,
                'packageSha256':NEW_PACKAGE_SHA,'changedModule':'host_pmem_cli.py',
                'existingAOwnerRestarted':False}
            super().save(value)

        def start_sdk(self,publication):
            self.stage_sources()
            return super().start_sdk(publication)

        def start_view(self,owner):
            self.stage_sources()
            return super().start_view(owner)

        def view_action(self,action):
            self.stage_sources()
            return super().view_action(action)

        def release_sdk(self,peer_receipt):
            self.stage_sources()
            return super().release_sdk(peer_receipt)

        def require_existing_owner(self):
            owner=self.state['owner'];expected=owner['process']
            status=m.unit(self.sdk_unit)
            need(status['ActiveState']=='active' and int(status['MainPID'])==expected['pid']
                 and m.measure.process_identity(expected['pid'])==expected['ticks'],'Existing SDK owner changed')
            journal=m.read_json(self.prep/'provider/owner.json')
            publication=m.read_json(self.prep/'provider/replicas.json')
            need(publication==owner['publication'] and journal.get('state')=='serving'
                 and journal.get('ownerId')==publication['ownerId']
                 and journal.get('manifestSha256')==m.workflow.manifest_identity(publication),
                 'Existing SDK publication is not exactly confirmed serving')
            rows=journal.get('objects',[])
            need(len(rows)==1 and rows[0].get('creation_confirmed') is True
                 and rows[0].get('delete_acknowledged') is False,'Existing object lifecycle differs')
            need(m.unit(self.view_unit)['LoadState']=='not-found'
                 and not (self.work/'view').exists(),'A root view was already submitted or created; no restart')

    class Workflow(original_flow):
        def envelope(self,kind,**values):
            return {**super().envelope(kind,**values),'activeCodeCoreCommit':FIX_CORE}

        def start(self,peer_token):
            if not getattr(m,'resume_existing_view',False):
                # A may not republish; B alone can start its first import.
                need(self.state['node']=='node-b','Use resume-view for the already published A owner')
                return super().start(peer_token)
            need(self.state['node']=='node-a' and self.state['phase']=='view_start_intent',
                 'Only the confirmed pre-view A failure may resume')
            need(not self.state.get('viewLaunchAttempted') and not self.state.get('viewResumeAttempted')
                 and 'view' not in self.state and peer_token is None,'View launch/resume was already attempted')
            self.ops.check_candidate();self.ops.require_existing_owner()
            self.mark('view_start_intent',viewResumeAttempted=True,
                      resumeScope='existing SDK publication, no SDK create/import/restart')
            view=self.ops.start_view(self.state['owner'])
            self.mark('view_serving',view=view)
            sample=self.ops.measure()
            publication=self.state['owner']['publication']
            token=self.envelope('publisher_ready',publication=publication,
                publicationIdentity=m.workflow.manifest_identity(publication),
                peerModuleDigest=m.workflow.digest(self.state['peerEvidence']),
                moduleReadyDigest=m.workflow.digest(self.state['moduleReady']),sample=sample)
            self.mark('data_ready',dataReady=token,sample=sample)
            return m.workflow.encode(token)

    def report(state,peer):
        value=original_report(state,peer)
        value['codeProvenance']=state.get('codeProvenance')
        return value
    m.Operations=Operations;m.workflow.Workflow=Workflow;m.report=report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('resume-view','start','release','restore','abort-no-sdk',
                                      'request-cancel','cancel-import','status','report'))
    parser.add_argument('--peer-token');parser.add_argument('--approval')
    args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0,'Expected root')
    path=Path(ENTRIES[platform.node()])
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    import stat
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
             and info.st_size==123698,'Original v2 entry identity differs')
        raw=stream.read(123699)
    need(hashlib.sha256(raw).hexdigest()==OLD_ENTRY_SHA,'Original v2 entry hash differs')
    m=types.ModuleType('frozen_host_pmem_v2');m.__file__=str(path)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    configure(m);m.resume_existing_view=args.mode=='resume-view'
    sys.argv=[str(path),'start' if m.resume_existing_view else args.mode]
    if args.peer_token is not None:sys.argv+=['--peer-token',args.peer_token]
    if args.approval is not None:sys.argv+=['--approval',args.approval]
    try:m.main()
    except Exception as error:
        print(json.dumps({'status':'HOST_PMEM_CONTINUATION_STOPPED_PRESERVE_STATE','reason':str(error),
            'activeCoreCommit':FIX_CORE,'automaticAllocationRetry':False,'automaticRollbackExecuted':False}))
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
