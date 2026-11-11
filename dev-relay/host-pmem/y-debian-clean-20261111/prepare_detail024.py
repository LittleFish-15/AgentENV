"""Prepare native detailed logging and a single formal100 diagnostic run."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'runtime_supervisor014.py').read_text(encoding='utf-8')
old="'AENV_LOG_FORMAT':'compact','RUST_LOG':'agentenv=warn'"
new="'AENV_LOG_FORMAT':'json','AENV_LOG_SPAN_EVENTS':'close','RUST_LOG':'agentenv=info,envd=info,uvm_ublk=info,agentenv::sandbox::firecracker::sandbox=debug'"
assert s.count(old)==1;s=s.replace(old,new)
(H/'runtime_supervisor024.py').write_bytes(s.encode());ast.parse(s,feature_version=(3,11))
worker=(H/'wikidata018_worker.py').read_text(encoding='utf-8').replace("BASE/'wikidata018'","BASE/'wikidata024'").replace('wikidata018.lock','wikidata024.lock').replace("BASE/'results/wikidata018'","BASE/'results/wikidata024'")
worker=worker.replace("[('prewarm100',1),('formal',5)]","[('prewarm100',1),('formal',1)]")
needle="            save(label+'_running',"
assert needle in worker;worker=worker.replace(needle,"            if label=='formal':STATE['formalServerLogOffset']=(BASE/'logs/server.log').stat().st_size\n"+needle)
# Parent returns raw benchmark+trace archive once; avoid nested duplicate archives.
a=worker.index('        archive=io.BytesIO()');b=worker.index("        assert finished",a)
worker=worker[:a]+worker[b:]
ast.parse(worker,feature_version=(3,11));(H/'wikidata024_worker.py').write_bytes(worker.encode())
print('024 prepared: JSON close/debug logging, prewarm100 and one formal100 round, exact original benchmark')
