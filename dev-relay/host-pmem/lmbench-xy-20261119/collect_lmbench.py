"""Bounded read-only collection of existing lmbench results; never run benchmarks."""
import base64, hashlib, json, os, platform, re, subprocess, sys, time
from pathlib import Path

def main():
    machine=sys.argv[1]
    assert machine in ('X','Y')
    assert platform.machine()==('aarch64' if machine=='X' else 'x86_64')
    roots=[]
    for parent in map(Path,('/data/jwk','/home/jwk','/root','/data/cxd','/home/cxd')):
        if not parent.is_dir():continue
        for p in parent.glob('*lmbench*'):
            if p.is_dir() and not p.is_symlink() and (p/'src/lat_mem_rd.c').is_file():roots.append(p)
    for parent in map(Path,('/data/jwk','/home/jwk')):
        if parent.is_dir():
            for p in parent.glob('*/lmbench-3.0-a9'):
                if not p.is_symlink() and (p/'src/lat_mem_rd.c').is_file() and p not in roots:roots.append(p)
    files=[];budget=0;packages=[]
    def add(p,kind):
        nonlocal budget
        st=p.stat()
        if st.st_size>240000 or budget+st.st_size>800000:return
        raw=p.read_bytes();budget+=len(raw)
        files.append({'path':str(p),'kind':kind,'bytes':len(raw),'mtimeUnix':st.st_mtime,'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()})
    for root in roots[:5]:
        item={'root':str(root),'binaryHashes':[]}
        for folder in ('results','Results'):
            d=root/folder
            if not d.is_dir():continue
            for p in sorted(d.glob('*/*')):
                if p.is_file() and re.search(r'\.\d+$',p.name):add(p,'result')
            for p in sorted(d.glob('*')):
                if p.is_file() and re.search(r'\.\d+$',p.name):add(p,'result')
        for p in sorted((root/'bin').glob('CONFIG*'))+sorted((root/'bin').glob('*/CONFIG*')):
            if p.is_file():add(p,'config')
        for name in ('src/lat_mem_rd.c','src/lib_mem.c','src/lib_timing.c','src/bench.h','src/Makefile','scripts/lmbench','scripts/results','scripts/build'):
            p=root/name
            if p.is_file():add(p,'source')
        for name in ('lmbench-build.log','lmbench-run.log','make-rerun.log'):
            p=root/name
            if p.is_file():add(p,'build_log' if 'build' in name else 'run_log')
        for d in [root/'bin']+[p for p in (root/'bin').glob('*') if p.is_dir()]:
            for name in ('lat_mem_rd','bw_mem','stream'):
                p=d/name
                if p.is_file() and p.stat().st_size<2000000:
                    item['binaryHashes'].append({'path':str(p),'bytes':p.stat().st_size,'mtimeUnix':p.stat().st_mtime,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
        packages.append(item)
    observations={}
    for name in ('/proc/cpuinfo','/proc/meminfo','/proc/loadavg','/sys/devices/system/node/online','/sys/kernel/mm/transparent_hugepage/enabled'):
        p=Path(name)
        if p.is_file():
            text=p.read_text(errors='replace')
            if name=='/proc/cpuinfo':text=text.split('\n\n')[0]
            observations[name]=text[:12000]
    observations['numaCpulists']={str(p):p.read_text().strip() for p in Path('/sys/devices/system/node').glob('node*/cpulist')}
    try:
        r=subprocess.run(['dmidecode','--type','17'],capture_output=True,text=True,timeout=10)
        observations['memoryDmi']=[line.strip() for line in r.stdout.splitlines() if re.match(r'\s*(?:Configured Memory Speed|Speed|Type|Size|Locator):',line)]
    except (OSError,subprocess.TimeoutExpired):observations['memoryDmi']=None
    active=[]
    for p in Path('/proc').glob('[0-9]*'):
        try:
            if (p/'comm').read_text().strip() not in ('lat_mem_rd','bw_mem','stream'):continue
            active.append({'pid':int(p.name),'args':(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')})
        except OSError:pass
    result={'schema':1,'machine':machine,'hostname':platform.node(),'architecture':platform.machine(),'kernel':platform.release(),'observedUnix':time.time(),'readOnly':True,'benchmarksExecuted':False,'roots':packages,'observations':observations,'activeMemoryBenchmarks':active,'files':files}
    print(json.dumps(result,separators=(',',':')),flush=True)

if __name__=='__main__':main()
