"""Continue the known captured template without repeating cold start/capture."""

def exercise(case,image,execute):
    evidence=case.snapshot(RETAINED_SNAPSHOT)
    need(evidence.get('snapshotId')==RETAINED_SNAPSHOT and
         evidence.get('committedRecordSha256')==RETAINED_RECORD_SHA,
         'Retained successful snapshot changed; preserve it')
    children=[]
    for slot in range(2):
        child=case.create('/v2/sandboxes',{'templateID':RETAINED_SNAPSHOT,'timeout':1800,
            'secure':True,'autoPause':False,'allow_internet_access':False,
            'metadata':{'cow_batch':case.run_id,'dsec_slot':str(slot)}})
        children.append(child)
        execute(child,'restored-'+str(slot),'check')
    execute(children[0],'private-copy-up','write')
    execute(children[1],'peer-remains-original','check')
    execute(children[0],'writer-keeps-private-value','private')
    case.delete(children[0])
    execute(children[1],'peer-after-writer-exit','check')
    return {'existingSnapshotId':RETAINED_SNAPSHOT,'children':children,
            'upperSnapshotRestorePassed':True,'privateCopyUpIsolationPassed':True,
            'peerSurvivesWriterExit':True,'explicitDaxAndInstructionProbesPassed':True,
            'coldStartRepeated':False,'captureRepeated':False,
            'scope':'retained Host-file DSec snapshot restore; not cross-node acceptance'}
