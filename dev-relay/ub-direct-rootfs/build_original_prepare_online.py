import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).parent
source=(HERE/'B_start_measurement_after_gate_v2.py').read_text()
source=source.replace('B_start_measurement_after_gate_v2.py','B_start_measurement_after_gate_v3.py')
source=source.replace('next-measure-resourcefix-','next-measure-prepared-')
source=source.replace('B-measurement-resourcefix-failure-','B-measurement-prepared-failure-')
hook="    print('ONLINE_PINNED_MEASUREMENT_PIPELINE_READY',flush=True)"
assert source.count(hook)==1
source=source.replace(hook,"    if phase.startswith('original-'):prepare_original_template(pipeline,node)\n"+hook)
hook="    pipeline.next_command('NEXT_A_ORIGINAL_COMMAND','original-a','a',context)"
assert source.count(hook)==1
source=source.replace(hook,"    prepare_original_template(pipeline,'b')\n"+hook)
marker="if __name__=='__main__':"
assert source.count(marker)==1
helper=(HERE/'prepare_original_measurement_template.py').read_text()
source=source.replace(marker,helper+'\n\n'+marker)
raw=source.encode();ast.parse(raw,feature_version=(3,11))
(HERE/'B_start_measurement_after_gate_v3.py').write_bytes(raw)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'pipelineUnchanged':True},indent=2))
