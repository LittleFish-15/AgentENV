import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).parent
packet=json.loads((HERE/'baseline-layout-fix-packet.json').read_text())
publication=json.loads((HERE/'baseline-layout-code-publication.json').read_text())
source=(HERE/'B_start_measurement_after_gate_v4.py').read_text()
old=(HERE/'prepare_original_measurement_template_v2.py').read_text();new=(HERE/'prepare_original_measurement_template_v3.py').read_text()
assert source.count(old)==1;source=source.replace(old,new)
source=source.replace('B_start_measurement_after_gate_v4.py','B_start_measurement_after_gate_v5.py')
source=source.replace('AB_deletefix_measurement_pipeline_v2.py','AB_deletefix_measurement_pipeline_v3.py')
source=source.replace('3f71837c7c13adb57c8889159b3e05dc63d80443',publication['commit'])
source=source.replace('710adbbbc7aaa41f939819d7d333dafeddaae5398b5ab2cbfad68120ed51f56f',packet['pipelineSha256'])
source=source.replace('PIPELINE_BYTES=215219','PIPELINE_BYTES='+str(packet['pipelineBytes']))
source=source.replace('next-measure-cli-ready-','next-measure-layout-ready-')
raw=source.encode();ast.parse(raw,feature_version=(3,11))
(HERE/'B_start_measurement_after_gate_v5.py').write_bytes(raw)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'pipelineCommit':publication['commit']},indent=2))
