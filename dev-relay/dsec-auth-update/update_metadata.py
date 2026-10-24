"""Compose a coordinated new Runtime installation without touching live files.

The root activation controller must retire the old owned Runtime before applying
these replacements. Credentials, config, provider, images and snapshots are not
replacement targets. This module performs no filesystem or service operations.
"""
import ast,copy,hashlib,json,re
from pathlib import Path
DEPLOYMENT='/home/jwk/agent/deployments/agentenv-dsec-hostfile-v1'
OLD_CORE='268104ecc65080d776c2301e09e7902686ac4253'
NEW_CORE='2c2c0ea573f97a0ce8fc64f2dfb79d60b7089a14'
NEW_TREE='90b0f08da903b7e5a0e433370d63da606f978442'
OLD_PREPARE='eaefa8cb41793ea0f61204f05e08229d4173efb7b0baebad8ad22480f77955dd'
OLD_SERVER='f279512d36c64e46903fdc1456c330f82ed1aadb9d928305522eea34348e211e'
TARGETS={'libexec/native_prepare.py','libexec/native_service.py','definition-native.json',
         'installation.json','input-manifest.json','definition.json','prepare.json'}

def require(ok,reason):
    if not ok:raise ValueError(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()

def assignment(source,key,value):
    matches=[n for n in ast.parse(source).body if isinstance(n,ast.Assign) and
        len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==key]
    require(len(matches)==1,'Expected exactly one adapter constant '+key)
    n=matches[0];lines=source.splitlines(keepends=True)
    return ''.join(lines[:n.lineno-1])+key+' = '+repr(value)+'\n'+''.join(lines[n.end_lineno:])

def compose(original,build_raw):
    require(set(original)==TARGETS,'Incomplete or extra metadata replacement scope')
    require(sha(original['libexec/native_prepare.py'])==OLD_PREPARE,'Original installed adapter differs')
    build=json.loads(build_raw)
    require(build.get('status')=='DSEC_AUTH_RUNTIME_BUILT_TESTED_NOT_DEPLOYED' and
        build.get('release',{}).get('coreCommit')==NEW_CORE and build['release'].get('tree')==NEW_TREE and
        build['release'].get('published') is True,'Fixed Runtime has no completed published build')
    require(set(build.get('phases',{}))=={'resolve-readiness-order-contract','test-readiness-order-contract','build-fixed-runtime'} and
        all(row.get('exitCode')==0 for row in build['phases'].values()),'Fixed Runtime build/tests incomplete')
    server=build['server']
    require(re.fullmatch('[0-9a-f]{64}',server.get('sha256','')) is not None and
        type(server.get('bytes')) is int and 0<server['bytes']<=128*1024**2,
        'Invalid fixed Runtime binary pin')
    capture=build.get('captureProvenance',{})
    require(capture.get('capturedBeforeRustcWrapperExit') is True and
        all(capture.get(key)==server.get(key) for key in ('path','bytes','sha256')) and
        Path(capture.get('sourceManifest','')).as_posix()==
            (Path(server['path']).parent.parent/'source/Cargo.toml').as_posix(),
        'Candidate was not captured from its compiler invocation')
    require(build.get('retainedCoreCommit')=='eb2301e7bd924784287f6c50d4faa4cabc7ca52b' and
        set(build.get('retainedArtifacts',{}))=={'aenv','uvm-ublk-daemon','aenv-native-fd-verify','firecracker'},
        'Untouched component provenance differs')
    definition=json.loads(original['definition-native.json'])
    installation=json.loads(original['installation.json'])
    manifest=json.loads(original['input-manifest.json'])
    base=json.loads(original['definition.json'])
    prepared=json.loads(original['prepare.json'])
    require(installation.get('commit')==base.get('commit')==OLD_CORE and
        installation.get('unit')=='jwk-aenv-dsec-hostfile-v1-node-a.service' and
        installation.get('node')==definition.get('node')=='node-a','Old deployment identity differs')
    require(installation.get('launcher_sha256')==sha(original['libexec/native_service.py']) and
        installation.get('launcher_dependencies',{}).get('native_prepare.py')==OLD_PREPARE,
        'Old launcher/dependency pins disagree')
    require(definition['binaries']['server']==installation['binaries']['server']==manifest['bin/server']['sha256']==OLD_SERVER,
        'Old Runtime pins disagree')
    for name in ('aenv','uvm-ublk-daemon','aenv-native-fd-verify'):
        require(build['retainedArtifacts'][name]['sha256']==definition['binaries'][name]==installation['binaries'][name],
            'Retained executable differs: '+name)
    require(build['retainedArtifacts']['firecracker']['sha256']==manifest['deps/firecracker/1.15.1-patch-v3/firecracker']['sha256'],
        'Retained Firecracker differs')
    source=original['libexec/native_prepare.py'].decode()
    source=assignment(source,'COMMIT',NEW_CORE);source=assignment(source,'CORE_TREE',NEW_TREE)
    require(source.count("        raise RuntimeError('Updated installed adapter cannot prepare a new deployment; use the fixed coordinator')\n")==1,'Previously updated adapter guard changed')
    ast.parse(source,feature_version=(3,11));prepare=source.encode()
    definition['binaries']['server']=server['sha256']
    provenance=definition['componentProvenance'];provenance['server']=NEW_CORE
    if 'buildReceiptSha256' in provenance:
        provenance['retainedBuildReceiptSha256']=provenance.pop('buildReceiptSha256')
    provenance['runtimeFixReceiptSha256']=sha(build_raw)
    definition_raw=encoded(definition)
    private={**json.loads(definition_raw),'prepareSourceSha256':sha(prepare),'definitionSha256':sha(definition_raw)}
    launcher=('import base64,hashlib,json,sys\nfrom pathlib import Path\n'+
        'p=Path('+repr(DEPLOYMENT+'/libexec/native_prepare.py')+');raw=p.read_bytes()\n'+
        'if hashlib.sha256(raw).hexdigest()!='+repr(sha(prepare))+":raise RuntimeError('Native adapter dependency changed')\n"+
        "scope={'__name__':'native_adapter','__file__':str(p)};exec(compile(raw,str(p),'exec'),scope)\n"+
        "scope['runtime_entry']("+repr(private)+",sys.argv[1:])\n").encode()
    ast.parse(launcher,feature_version=(3,11))
    installation['commit']=NEW_CORE;installation['binaries']['server']=server['sha256']
    installation['launcher_sha256']=sha(launcher)
    installation['launcher_dependencies']['native_prepare.py']=sha(prepare)
    manifest['bin/server']={'bytes':server['bytes'],'sha256':server['sha256']}
    base['commit']=NEW_CORE
    prepared.update(status='DSEC_RUNTIME_FIX_STAGED_NOT_ACTIVATED',runtimeSourceCommit=NEW_CORE,
        componentProvenance=copy.deepcopy(provenance),runtime_started=False,
        stageScope='Runtime executable and coherent metadata replacement; Guest acceptance pending',
        next_action='Use the pinned update coordinator to activate and validate')
    return {'libexec/native_prepare.py':prepare,'libexec/native_service.py':launcher,
        'definition-native.json':definition_raw,'installation.json':encoded(installation),
        'input-manifest.json':encoded(manifest),'definition.json':encoded(base),'prepare.json':encoded(prepared)}
