"""One public online entry: B starts from saved gate, A uses relayed context."""
import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).parent
publication=json.loads((HERE/'resource-schema-code-publication.json').read_text())
packet=json.loads((HERE/'resource-schema-fix-packet.json').read_text())
source=(HERE/'AB_deletefix_measurement_online_v3.py').read_text()
source=source.replace('AB_deletefix_measurement_online_v3.py','B_start_measurement_after_gate_v2.py')
source=source.replace('AB_deletefix_measurement_pipeline_v1.py','AB_deletefix_measurement_pipeline_v2.py')
source=source.replace('12549737c5dc557d5f821068e6d656818a1709a5',publication['commit'])
source=source.replace('87aa3faed883da757e3bd9d8ac22123a1954f0a1407b6ae062bb8a89d4af14ca',packet['pipelineSha256'])
source=source.replace('PIPELINE_BYTES=213935','PIPELINE_BYTES='+str(packet['pipelineBytes']))
source=source.replace("    need(phase.endswith('-'+node),'Wrong node for phase')",
                      "    need(phase in ('original-a','original-b','full-a','full-b') and phase.endswith('-'+node),'Measurement phase/node required')")
source=source.replace('unchanged pinned measurement pipeline','resource-schema-corrected measurement pipeline')
source=source.replace('unchanged public pipeline','fixed public pipeline')

starter=(HERE/'B_start_measurement_after_gate_v1.py').read_text()
starter=starter[starter.index('import argparse'):]
start=starter.index("RELEASE='43");end=starter.index('\ndef need(',start)
starter=starter[:start]+"RELEASE=None\nSHA=None\nSIZE=None\n"+starter[end:]
start=starter.index('def online_module():');end=starter.index('\ndef main():',start)
starter=starter[:start]+'''def online_module():
    module=types.ModuleType('resourcefix_online_transport')
    module.__dict__.update(globals())
    return module

'''+starter[end:]
starter=starter.replace("def main():\n", "def main():\n    global RELEASE,SHA,SIZE\n")
starter=starter.replace("parser.add_argument('--run',action='store_true');args=parser.parse_args()",
 "parser.add_argument('--run',action='store_true');parser.add_argument('--release');args=parser.parse_args()")
starter=starter.replace("    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')",
 "    need(ROOT.resolve(strict=True)==ROOT,'Agent directory redirected')\n    need(isinstance(args.release,str) and re.fullmatch('[0-9a-f]{40}',args.release),'Fixed public release required')\n    RELEASE=args.release\n    entry=Path(__file__).read_bytes();SHA=hashlib.sha256(entry).hexdigest();SIZE=len(entry)")
starter=starter.replace('next-measure-online-','next-measure-resourcefix-')
starter=starter.replace('B-measurement-start-failure-','B-measurement-resourcefix-failure-')
starter=starter.replace("    print('B_MEASUREMENT_STATE '","    print('RESOURCE_SCHEMA_FIXED cpu_count memory_mib disk_size_mib; complete resource identity retained',flush=True)\n    print('B_MEASUREMENT_STATE '")
raw=(source+'\n\n'+starter).encode()
ast.parse(raw,feature_version=(3,11))
(HERE/'B_start_measurement_after_gate_v2.py').write_bytes(raw)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'pipelineCommit':publication['commit']},indent=2))
