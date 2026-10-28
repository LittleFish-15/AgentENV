import ast,base64,hashlib,json,tarfile,zlib
from pathlib import Path
HERE=Path(__file__).parent
def unpack(file,key):
    s=(HERE/file).read_text();tree=ast.parse(s)
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and n.targets[0].id==key)),s.split('\n',1)[1]
def packed(raw,filename=None):
    if isinstance(raw,str):raw=raw.encode()
    ast.parse(raw,feature_version=(3,11))
    r={'sha256':hashlib.sha256(raw).hexdigest(),'z64':base64.b64encode(zlib.compress(raw,9)).decode()}
    r.update({'filename':filename} if filename else {'bytes':len(raw)});return r
def replace(s,a,b):assert s.count(a)==1,(a,s.count(a));return s.replace(a,b)
archive=HERE.parent/'agentenv-deploy-20261017/assets/firecracker-1.15.1-patch-v3-aarch64.tgz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='8f890acff9ea9209dd004d2d5b0af43ee0de5bb6ff3e2ff0a88407fcc15e808d'
with tarfile.open(archive) as t:original=t.extractfile('firecracker').read()
assert len(original)==3190408 and hashlib.sha256(original).hexdigest()=='a64b8f068d47bd6ec85aa755b8f8863e16d0ae14be551376218fed401ee0bdf8'
modules,body=unpack('AB_deletefix_local_comparison_v3.py','MODULES')
admission=zlib.decompress(base64.b64decode(modules['admission']['z64'])).decode()
extra='''
FC_BUILDS={
 'original':{'sha256':'a64b8f068d47bd6ec85aa755b8f8863e16d0ae14be551376218fed401ee0bdf8','bytes':3190408},
 'full':{'sha256':'e9588526096f45380b8debf2d41bf33a2fb26f8abea0a9bed841627327782a0b','bytes':7629744}}

def validate_fc(variant,digest,length):
    expected=FC_BUILDS[variant]
    need(digest==expected['sha256'] and type(length) is int and length==expected['bytes'],
         'FC does not match fixed '+variant+' artifact: actual_sha256='+str(digest)+' actual_bytes='+str(length))
    return dict(expected)

'''
admission=replace(admission,'def input_signature(templates):',extra+'def input_signature(templates):')
modules['admission']=packed(admission)
body=replace(body,"need(fc_sha==self.runtime.binaries['firecracker']['sha256'], 'Original/full FC binary differs')",
             "self.gates.validate_fc(variant,fc_sha,fc.stat().st_size)\n            context['firecrackerBytes']=fc.stat().st_size\n            context['comparisonBuildScope']='genuine-original-stack-vs-full-UB-stack; FC differs; no UB-only causal attribution'")
raw=('MODULES='+repr(modules)+'\n'+body).encode();(HERE/'AB_deletefix_local_comparison_v4.py').write_bytes(raw)
(HERE/'variant_fc_admission.py').write_text(admission,encoding='utf-8',newline='\n')
(HERE/'variant_fc_comparison_body.py').write_text(body,encoding='utf-8',newline='\n')
aggmodules,agg=unpack('aggregate_deletefix_comparison_v3.py','MODULES');aggmodules['admission']=modules['admission']
agg=replace(agg,hashlib.sha256((HERE/'AB_deletefix_local_comparison_v3.py').read_bytes()).hexdigest(),hashlib.sha256(raw).hexdigest())
agg=replace(agg,"need(re.fullmatch('[0-9a-f]{32}',receipt['runId']) is not None,'Invalid comparison run ID')",
 "modules['admission'].validate_fc(variant,context['firecrackerSha256'],context['firecrackerBytes'])\n    need(re.fullmatch('[0-9a-f]{32}',receipt['runId']) is not None,'Invalid comparison run ID')")
agg=replace(agg,"'guestsPerVariantAcrossNodes':4,'templates':1,'sixteenGuestTargetCompleted':False,",
 "'guestsPerVariantAcrossNodes':4,'templates':1,'sixteenGuestTargetCompleted':False,\n        'comparisonBuildScope':'genuine-original-stack-vs-full-UB-stack','firecrackerBuilds':modules['admission'].FC_BUILDS,'UBOnlyCausalAttribution':False,")
agg=replace(agg,"'caveats':['Node baseline/final sampling windows are separate, not an atomic cluster snapshot.',",
 "'caveats':['Original and full retain their respective pinned FC builds; whole-stack differences are not isolated UB effects.',\n            'Node baseline/final sampling windows are separate, not an atomic cluster snapshot.',")
agraw=('MODULES='+repr(aggmodules)+'\n'+agg).encode();(HERE/'aggregate_deletefix_comparison_v4.py').write_bytes(agraw)
(HERE/'variant_fc_aggregation_body.py').write_text(agg,encoding='utf-8',newline='\n')
components,pipeline=unpack('AB_deletefix_measurement_pipeline_v3.py','COMPONENTS')
components['comparison']=packed(raw,'AB_deletefix_local_comparison_v4.py');components['aggregate']=packed(agraw,'aggregate_deletefix_comparison_v4.py')
pipeline=pipeline.replace('AB_deletefix_measurement_pipeline_v3.py','AB_deletefix_measurement_pipeline_v4.py').replace('next-layoutfix-','next-fc-pinned-')
pipeline=replace(pipeline,"'uniqueRetainedUBReservation':reservation,'netSavingsBytes':None,'outputDirectory':str(comp.WORK/variant)",
 "'uniqueRetainedUBReservation':reservation,'netSavingsBytes':None,'firecrackerBuild':{'sha256':receipt['context']['firecrackerSha256'],'bytes':receipt['context']['firecrackerBytes']},'comparisonBuildScope':receipt['context']['comparisonBuildScope'],'outputDirectory':str(comp.WORK/variant)")
final=('COMPONENTS='+repr(components)+'\n'+pipeline).encode();(HERE/'AB_deletefix_measurement_pipeline_v4.py').write_bytes(final)
for value in (raw,agraw,final):ast.parse(value,feature_version=(3,11))
record={'pipelineSha256':hashlib.sha256(final).hexdigest(),'pipelineBytes':len(final),'controllerSha256':hashlib.sha256(raw).hexdigest(),
 'aggregateSha256':hashlib.sha256(agraw).hexdigest(),'baselineArchiveSha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
 'baselineFCExtractedSha256':hashlib.sha256(original).hexdigest(),'baselineFCBytes':len(original),'targetOriginalFCChecksumStillRequiresValidation':True,
 'scope':'fixed per-variant FC identities; whole-stack comparison explicitly labelled; no binary switch or UB-only causal claim'}
(HERE/'variant-fc-packet.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
