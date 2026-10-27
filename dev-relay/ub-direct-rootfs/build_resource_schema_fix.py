"""Build new measurement versions, preserving all prior packets and field state."""
import ast,base64,hashlib,json,zlib
from pathlib import Path
HERE=Path(__file__).parent

def unpack(filename,key):
    raw=(HERE/filename).read_text(encoding='utf-8')
    tree=ast.parse(raw)
    assert isinstance(tree.body[0],ast.Assign) and tree.body[0].targets[0].id==key
    return ast.literal_eval(tree.body[0].value),raw.split('\n',1)[1]

def decode(row):
    raw=zlib.decompress(base64.b64decode(row['z64']))
    assert hashlib.sha256(raw).hexdigest()==row['sha256']
    return raw.decode()

def pack(raw,filename=None):
    if isinstance(raw,str):raw=raw.encode()
    ast.parse(raw,feature_version=(3,11))
    result={'sha256':hashlib.sha256(raw).hexdigest(),'z64':base64.b64encode(zlib.compress(raw,9)).decode()}
    if filename:result['filename']=filename
    else:result['bytes']=len(raw)
    return result

HELPER='''
def valid_resources(value):
    # Exact serde schema from aenv src/types/resources.rs. Do not drop disk
    # capacity from the frozen input, workload digest or pair comparison.
    return (type(value) is dict and set(value)=={'cpu_count','memory_mib','disk_size_mib'}
            and all(type(value[k]) is int and 0<value[k]<=4294967295 for k in value)
            and value['cpu_count']==2 and value['memory_mib']==4096)

'''

def change(source,old,new,count=1):
    assert source.count(old)==count,(old,source.count(old))
    return source.replace(old,new)

def helper(source):return source.replace('\ndef need(',HELPER+'\ndef need(',1)

modules,body=unpack('AB_deletefix_local_comparison_v1.py','MODULES')
for name in ('admission','cohort','native_replay'):
    source=helper(decode(modules[name]))
    expression="job['resources']" if name=='native_replay' else ("row['resources']" if name=='admission' else "r['resources']")
    source=change(source,expression+"=={'cpu_count':2,'memory_mib':4096}",'valid_resources('+expression+')')
    if name=='native_replay':
        source=change(source,"j['resources']['cpu_count'],j['resources']['memory_mib'],",
                      "json.dumps(j['resources'],sort_keys=True,separators=(',',':')),")
        # Also reject mismatched resource objects in completed receipt rows,
        # independently of the persisted workload hash.
        source=change(source,"left,right=a[key],b[key]","left,right=a[key],b[key]\n        need(valid_resources(left['resources']) and left['resources']==right['resources'],'Completed job resources differ')")
    modules[name]=pack(source)
    (HERE/('resourcefix_'+name+'.py')).write_text(source,encoding='utf-8',newline='\n')
controller=('MODULES='+repr(modules)+'\n'+body).encode()
(HERE/'AB_deletefix_local_comparison_v2.py').write_bytes(controller)
controller_pin=hashlib.sha256(controller).hexdigest()

agg_modules,agg=unpack('aggregate_deletefix_comparison_v1.py','MODULES')
old_controller=ast.literal_eval(next(n.value for n in ast.parse(agg).body if isinstance(n,ast.Assign) and n.targets[0].id=='CONTROLLER'))
agg=change(agg,repr(old_controller),repr(controller_pin))
agg=change(agg,"signature[3]=={'cpu_count':2,'memory_mib':4096}","modules['admission'].valid_resources(signature[3])")
agg=change(agg,"job['resources']=={'cpu_count':2,'memory_mib':4096}","job['resources']==signature[3]")
agg_modules['admission']=modules['admission'];agg_modules['replay']=modules['native_replay']
aggregate=('MODULES='+repr(agg_modules)+'\n'+agg).encode()
(HERE/'aggregate_deletefix_comparison_v2.py').write_bytes(aggregate)
(HERE/'resourcefix_aggregation_body.py').write_text(agg,encoding='utf-8',newline='\n')

components,pipeline=unpack('AB_deletefix_measurement_pipeline_v1.py','COMPONENTS')
components['comparison']=pack(controller,'AB_deletefix_local_comparison_v2.py')
components['aggregate']=pack(aggregate,'aggregate_deletefix_comparison_v2.py')
pipeline=pipeline.replace('AB_deletefix_measurement_pipeline_v1.py','AB_deletefix_measurement_pipeline_v2.py')
pipeline=pipeline.replace("'next-'","'next-resourcefix-'")
pipeline_raw=('COMPONENTS='+repr(components)+'\n'+pipeline).encode()
(HERE/'AB_deletefix_measurement_pipeline_v2.py').write_bytes(pipeline_raw)
for raw in (controller,aggregate,pipeline_raw):ast.parse(raw,feature_version=(3,11))
record={'controllerSha256':controller_pin,'aggregateSha256':hashlib.sha256(aggregate).hexdigest(),
        'pipelineSha256':hashlib.sha256(pipeline_raw).hexdigest(),'pipelineBytes':len(pipeline_raw),
        'unchangedComponents':[k for k in modules if k not in ('admission','cohort','native_replay')],
        'exitControllerUnchanged':components['exit_pair']['sha256'],
        'scope':'three-field resource schema, full resource identity comparison; no lifecycle/replay timing/sampler/backend changes',
        'targetExecuted':False}
(HERE/'resource-schema-fix-packet.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
