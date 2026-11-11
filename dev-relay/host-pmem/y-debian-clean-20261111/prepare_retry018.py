"""Reuse the ready native template; repeat unchanged benchmark without repair."""
import ast
from pathlib import Path
H=Path(__file__).resolve().parent
s=(H/'wikidata017_worker.py').read_text(encoding='utf-8').replace("BASE/'wikidata017'","BASE/'wikidata018'").replace('wikidata017.lock','wikidata018.lock').replace("BASE/'results/wikidata017'","BASE/'results/wikidata018'")
s=s.replace("        assert not [row for row in api('GET','/templates') if NAME in row.get('names',[]) or NAME in row.get('aliases',[])],'Existing template must be reconciled'\n",'')
s=s.replace("        assert not (BASE/'config/bench_image_map.json').exists(),'Existing image map preserved'\n",'')
a=s.index("        save('image_resolution')");b=s.index("        assert api('GET','/v2/sandboxes?limit=100')==[]",a)
s=s[:a]+'''        previous=json.loads((BASE/'wikidata017/result.json').read_text())
        sid=previous['templateId'];bid=previous['buildId']
        assert previous['buildStatus']['status']=='ready'
        row=next(r for r in api('GET','/templates') if r['templateID']==sid)
        assert row['cpuCount']==2 and row['memoryMB']==4096 and row.get('buildStatus','ready')=='ready'
        assert json.loads((BASE/'config/bench_image_map.json').read_text())=={NAME:sid}
        save('existing_template_ready',templateId=sid,buildId=bid,template=row,image=previous['image'],imageProof=previous['imageProof'])
'''+s[b:]
ast.parse(s,feature_version=(3,11));(H/'wikidata018_worker.py').write_bytes(s.encode())
print('Retry018 reuses existing template and exact benchmark; no deployment or parameter change')
