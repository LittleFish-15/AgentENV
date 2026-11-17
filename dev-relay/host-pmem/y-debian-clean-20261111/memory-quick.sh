#!/usr/bin/env bash
set -eu
case "${1:-quick}" in
  -h|--help) printf '%s\n' 'Usage: bash /home/jwk/memory-quick.sh [quick|read|copy|latency|all]' 'quick (default): 16-thread read bandwidth + single-probe latency; 1 GiB, 3 internal samples.'; exit 0 ;;
esac
python3 -I -B - "${1:-quick}" <<'PY'
import hashlib,importlib.util,json,os,pathlib,platform,subprocess,sys
P=pathlib.Path
assert os.geteuid()==0,'Run this existing root-owned tool in a root terminal'
machine={'aarch64':'X','x86_64':'Y'}.get(platform.machine());assert machine,'Unsupported architecture'
root=P('/home/jwk')/('xy-memory-study-20261117-'+machine+'-046')
spec=importlib.util.spec_from_file_location('study',root/'memory_study.py')
expected={'X':'298428c6f0724d20110820bf86340669cbab08c93d79fee55b1d2f1a327e7332','Y':'6cf1c79bf79d95438fde34a64bbe7d47c4783b7477447dc823ac708f56922a35'}
assert hashlib.sha256((root/'memory_study.py').read_bytes()).hexdigest()=='000231d53f2c6f424cb18f01b3ea5f79c7efb6833981f019e73ec47ac3bee345'
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)
plan=json.loads((root/'ram-local/manifest.json').read_text());cpus=plan['selected_physical_cpus'];assert len(cpus)==16
binary=root/'build'/platform.machine()/'source/multiload';assert hashlib.sha256(binary.read_bytes()).hexdigest()==expected[machine]
mode=sys.argv[1];assert mode in ('quick','read','copy','latency','all'),'Use quick, read, copy, latency or all'
jobs={'quick':['read','latency'],'all':['read','copy','latency']}.get(mode,[mode])
base=[str(root/'private-bin/numactl'),'--physcpubind='+','.join(map(str,cpus)),'--membind=0',str(binary),'-a','-v','-n','3','-s','128','-p','4096']
env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
print('Machine=%s NUMA=0 physical_cores=16 working_set=1GiB samples=3'%machine,flush=True)
for job in jobs:
 latency=job=='latency';threads=1 if latency else 16;size=1073741824 if latency else 67108864;pattern='simple' if latency else 'stream-sum' if job=='read' else 'stream-copy'
 args=base+['-t',str(threads),'-m',str(size)]+(['-c','simple'] if latency else ['-l',pattern])
 print('Running '+job+' ...',flush=True)
 child=subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
 try:stdout,stderr=child.communicate(timeout=90)
 except BaseException:
  import signal
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
  raise
 assert child.returncode==0,stderr.decode(errors='replace')[-2000:]
 case={'per_worker_bytes':size,'load_threads':0 if latency else threads,'mode':'latency' if latency else 'bandwidth_total'}
 result=study.parse_output(stdout.decode(),case)
 if latency:print('LATENCY_NS=%.3f'%result['latency_ns'],flush=True)
 else:print('%s_16_THREADS_GiB_S=%.3f'%(job.upper(),result['bandwidth_gib_s']),flush=True)
PY
