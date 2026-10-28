"""Reduce actual rootfs observer events; no I/O generation or target access.

This is Host lower-call timing, not Guest syscall timing or UB wire bandwidth.
Only completed reads entirely within the declared monotonic window are used.
"""
import argparse
import json
import math
from pathlib import Path


def locality(event,mapping):
    if event.get('kind')=='read':return 'ordinary-file'
    if event.get('from_ub') is not True:return 'repository-fallback'
    ranges=mapping.get('rangesByDigest',{}).get(event.get('digest'),[])
    start=event['offset'];stop=start+event['bytes'];cursor=start;classes=set()
    for r in sorted(ranges,key=lambda x:x['fileOffset']):
        a=max(start,r['fileOffset']);b=min(stop,r['fileOffset']+r['bytes'])
        if a>=b:continue
        if a!=cursor or r['locality'] not in ('local','cross-node','mixed'):return 'unknown'
        cursor=b;classes.add(r['locality'])
    if cursor!=stop or not classes:return 'unknown'
    return next(iter(classes)) if len(classes)==1 else 'mixed'


def size_bucket(count):
    if count<=4096:return '<=4KiB'
    if count<=65536:return '4-64KiB'
    if count<=262144:return '64-256KiB'
    return '>256KiB'


def distribution(values):
    if not values:return {'count':0,'meanNs':None,'p50Ns':None,'p95Ns':None,'p99Ns':None,'maxNs':None}
    ordered=sorted(values)
    result={'count':len(values),'meanNs':sum(values)/len(values),'maxNs':ordered[-1]}
    for q in (50,95,99):result['p'+str(q)+'Ns']=ordered[math.ceil(q*len(values)/100)-1]
    result['tailSampleWarning']=len(values)<100
    return result


def summarize(events,source_map,window_start,window_end,observer):
    if type(window_start) is not int or type(window_end) is not int or window_end<=window_start:
        raise ValueError('Expected a bounded positive monotonic measurement window')
    groups={};windows={};sandboxes={};all_latencies=[];total_bytes=0;raw_count=0;invalid=unattributed=boundary=non_lower=0
    for event in events:
        raw_count+=1
        if raw_count>1000000:raise ValueError('Trace exceeds explicit one-million-record analysis bound')
        if event.get('kind') not in ('read','content_read'):continue
        a,b,count,offset=(event.get(k) for k in ('start_ns','end_ns','bytes','offset'))
        if any(type(x) is not int for x in (a,b,count,offset)) or a<=0 or b<a or count<=0 or offset<0:
            invalid+=1;continue
        if b<window_start or a>=window_end:continue
        if a<window_start or b>=window_end:boundary+=1;continue
        if event.get('allowed_lower') is False:non_lower+=1;continue
        if event.get('allowed_lower') is not True:invalid+=1;continue
        meta=source_map.get(event.get('source'))
        if not isinstance(meta,dict) or not isinstance(meta.get('sandboxId'),str):
            unattributed+=1;continue
        route=locality(event,meta)
        key=(meta['sandboxId'],route,size_bucket(count))
        group=groups.setdefault(key,{'bytes':0,'latencies':[]})
        group['bytes']+=count;group['latencies'].append(b-a)
        total_bytes+=count;all_latencies.append(b-a)
        sandbox=sandboxes.setdefault(meta['sandboxId'],{'bytes':0,'latencies':[]})
        sandbox['bytes']+=count;sandbox['latencies'].append(b-a)
        second=(b-window_start)//1000000000
        bucket=windows.setdefault((meta['sandboxId'],second),{'bytes':0,'latencies':[]})
        bucket['bytes']+=count;bucket['latencies'].append(b-a)
    seconds=(window_end-window_start)/1e9
    complete=(observer.get('read_tracking_version')==1
        and all(observer.get(k)==0 for k in ('dropped_records','errors','unsupported_context_calls',
                                            'active_reads','failed_or_cancelled_reads'))
        and isinstance(observer.get('drained_through_ns'),int) and observer['drained_through_ns']>=window_end
        and observer.get('records_written')==raw_count and invalid==unattributed==boundary==0)
    rows=[]
    for (sandbox,route,size),group in sorted(groups.items()):
        rows.append({'sandboxId':sandbox,'locality':route,'readSize':size,'completedBytes':group['bytes'],
            'windowAverageMiBps':group['bytes']/1048576/seconds,'windowAverageIOPS':len(group['latencies'])/seconds,
            'successfulLatency':distribution(group['latencies'])})
    series=[]
    for (sandbox,second),group in sorted(windows.items()):
        width=min(1.,seconds-second)
        series.append({'sandboxId':sandbox,'second':second,'actualWindowSeconds':width,
            'completedMiBps':group['bytes']/1048576/width,'completedIOPS':len(group['latencies'])/width,
            'successfulLatency':distribution(group['latencies'])})
    return {'scope':'Host lower-call latency; not Guest syscall or physical UB link performance',
        'windowStartNs':window_start,'windowEndNs':window_end,'windowSeconds':seconds,
        'completeWindowAccepted':complete,'rawRecords':raw_count,'invalidRecords':invalid,
        'unattributedRecords':unattributed,'boundaryRecordsExcluded':boundary,'nonLowerReadRecordsExcluded':non_lower,'observer':observer,
        'completedBytesIncludingRepeatedReads':total_bytes,'windowAverageMiBps':total_bytes/1048576/seconds,
        'windowAverageIOPS':len(all_latencies)/seconds,'successfulLatency':distribution(all_latencies),
        'latencySamplesNsForExactMerge':all_latencies,'groups':rows,'oneSecondWindows':series,
        'perSandbox':[{'sandboxId':name,'completedBytes':group['bytes'],
            'windowAverageMiBps':group['bytes']/1048576/seconds,'windowAverageIOPS':len(group['latencies'])/seconds,
            'successfulLatency':distribution(group['latencies'])} for name,group in sorted(sandboxes.items())],
        'missingWindowsAreNotAutomaticallyZero':True,'crossHostClockSubtractionUsed':False,
        'pureRemoteLatencyMeasured':False,'physicalLinkBandwidthMeasured':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace',required=True);parser.add_argument('--sources',required=True)
    parser.add_argument('--observer',required=True);parser.add_argument('--start-ns',type=int,required=True)
    parser.add_argument('--end-ns',type=int,required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    with open(args.trace,encoding='utf-8') as source:
        result=summarize((json.loads(line) for line in source if line.strip()),
            json.loads(Path(args.sources).read_text()),args.start_ns,args.end_ns,
            json.loads(Path(args.observer).read_text()))
    with open(args.output,'x',encoding='utf-8') as out:json.dump(result,out,indent=2)


if __name__=='__main__':main()
