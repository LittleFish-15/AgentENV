import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).parent
packet=json.loads((HERE/'variant-fc-packet.json').read_text());pub=json.loads((HERE/'variant-fc-code-publication.json').read_text())
s=(HERE/'B_start_measurement_after_gate_v5.py').read_text()
s=s.replace('B_start_measurement_after_gate_v5.py','B_start_measurement_after_gate_v6.py')
s=s.replace('AB_deletefix_measurement_pipeline_v3.py','AB_deletefix_measurement_pipeline_v4.py')
s=s.replace('168beebfe2a8b6025dfe1becfa9e486aaf3a0d72',pub['commit'])
s=s.replace('2c27ee9672e03c02d786e86677eec0e6f5fd5a6e59499491b7de7a862308740f',packet['pipelineSha256'])
s=s.replace('PIPELINE_BYTES=216333','PIPELINE_BYTES='+str(packet['pipelineBytes']))
s=s.replace('next-measure-layout-ready-','next-measure-fc-pinned-')
raw=s.encode();ast.parse(raw,feature_version=(3,11));(HERE/'B_start_measurement_after_gate_v6.py').write_bytes(raw)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'pipelineCommit':pub['commit']},indent=2))
