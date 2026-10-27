import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).parent
helper=(HERE/'prepare_original_measurement_template.py').read_text()
old="""    credential=tomllib.loads(rt.read(original/'cli/config/aenv/credentials').decode())
    match=re.fullmatch(r'http://127\\.0\\.0\\.1:(180[0-9]{2})',credential['url']);prep_need(match is not None,'Unexpected baseline endpoint')
    api=rt.Api(original,context['unit'],int(match[1]))
    prep_need(api.pid==context['pid'] and api.ticks==context['startTicks'] and api.key==credential['api_key'],'Original process/credential changed')"""
new="""    api=rt.Api(original,context['unit'],baseline_endpoint(env))
    prep_need(api.pid==context['pid'] and api.ticks==context['startTicks'],'Original process identity changed')"""
assert helper.count(old)==1;helper=helper.replace(old,new)
needle="    guard()\n    seed=json.loads(rt.read(source/'rootfs-inputs.json'))"
assert helper.count(needle)==1
helper=helper.replace(needle,"    guard()\n    print('BASELINE_CLI_PREPARATION '+json.dumps(baseline_cli_config(original,api,rt.read)),flush=True)\n    seed=json.loads(rt.read(source/'rootfs-inputs.json'))")
helper=(HERE/'baseline_measurement_cli.py').read_text()+'\n\n'+helper
(HERE/'prepare_original_measurement_template_v2.py').write_text(helper,encoding='utf-8',newline='\n')
source=(HERE/'B_start_measurement_after_gate_v3.py').read_text()
oldhelper=(HERE/'prepare_original_measurement_template.py').read_text()
assert source.count(oldhelper)==1;source=source.replace(oldhelper,helper)
source=source.replace('B_start_measurement_after_gate_v3.py','B_start_measurement_after_gate_v4.py')
source=source.replace('next-measure-prepared-','next-measure-cli-ready-')
raw=source.encode();ast.parse(raw,feature_version=(3,11))
(HERE/'B_start_measurement_after_gate_v4.py').write_bytes(raw)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'measurementPipelineUnchanged':True},indent=2))
