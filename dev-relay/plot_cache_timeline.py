"""Offline matplotlib PNG/SVG charts from returned cache time-series evidence.

Run on the analysis workstation. No target access, plotting dependency installs,
interpolation, smoothing, or synthetic replacement of missing observations.
"""
import argparse, hashlib, json, math
from pathlib import Path


def render(source,output,synthetic_preview=False):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    raw=Path(source).read_bytes()
    if len(raw)>128*1024**2:raise ValueError('Oversized source report')
    report=json.loads(raw);t=report.get('cache_timeseries',report)
    status=report.get('validation',{}).get('status','STATUS_NOT_PROVIDED')
    accepted=status=='COW4_GLOBAL_CACHE_MEASURED_GUESTS_RELEASED_ORIGINAL_RESTORED'
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    host=t['host_rows'];files=t['file_rows'];templates=t['template_rows'];bases=t['baselines']
    if not host or not files:raise ValueError('No measured host/file timeline to plot')
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,
                         'axes.grid':True,'grid.alpha':.2,'svg.fonttype':'none'})
    colors={'host':'#334155','lower':'#007f86','union':'#2563eb','shared':'#c2410c','other':'#7c3aed','residual':'#b91c1c'}
    origin=min(r['monotonic_ns'] for r in host);mib=1024**2;created=[]
    def seconds(r):return (r['monotonic_ns']-origin)/1e9
    def values(rows,key):return [r[key]/mib if type(r.get(key)) in (int,float) else float('nan') for r in rows]
    def save(fig,name,note):
        fig.text(.02,.015,note,fontsize=8,color='#475569')
        if not accepted and not synthetic_preview:
            fig.text(.98,.99,'INCOMPLETE OR RUN STATUS UNVERIFIED',ha='right',va='top',fontsize=9,color='#b91c1c')
        if synthetic_preview:fig.text(.5,.5,'SYNTHETIC QA ONLY — NOT EXPERIMENT DATA',ha='center',rotation=18,alpha=.22,fontsize=23,color='red')
        for suffix in ('png','svg'):
            path=output/(name+'.'+suffix);fig.savefig(path,dpi=180,bbox_inches='tight');created.append(path.name)
        plt.close(fig)
    # Absolute host and file cache use separate aligned panels; no hidden dual axis.
    fig,axes=plt.subplots(2,1,figsize=(12,8),sharex=True)
    axes[0].plot([seconds(r) for r in host],values(host,'Cached'),color=colors['host'],label='Host Cached')
    for key,color in [('Buffers','#94a3b8'),('Shmem','#a855f7')]:
        axes[0].plot([seconds(r) for r in host],values(host,key),color=color,label='Host '+key,alpha=.8)
    seen=set()
    for phase in ('idle_control','replay'):
        rows=[r for r in files if r['phase']==phase]
        for key,label,color in [('lower_resident_bytes','Full rootfs lower cache',colors['lower']),
                                ('accessed_resident_union_bytes','Accessed-resident union',colors['union']),
                                ('same_template_shared_resident_union_bytes','Pair-shared pages, globally deduplicated',colors['shared'])]:
            axes[1].plot([seconds(r) for r in rows],values(rows,key),'.-',color=color,label=label if label not in seen else None,markersize=3)
            seen.add(label)
    for event in t.get('global_drop_events',[]):
        drop=event['root_drop'];x=(drop['finished_monotonic_ns']-origin)/1e9
        for ax in axes:ax.axvline(x,color='#64748b',linestyle=':',alpha=.8)
        axes[0].annotate('drop: '+event['phase'],xy=(x,1),xycoords=('data','axes fraction'),xytext=(3,-6),textcoords='offset points',rotation=90,va='top',fontsize=8)
    for ax in axes:ax.set_ylabel('MiB');ax.legend(loc='best',fontsize=8)
    axes[0].set_title('Host page cache and measured rootfs cache — absolute observations')
    axes[1].set_xlabel('Seconds since first host sample');fig.tight_layout(rect=(0,.05,1,1))
    save(fig,'cache-global-absolute','Separate y-scales; actual timestamps. Lower cache deduplicated by inode. Disconnected phases are not interpolated across cache drops.')
    # Each phase has its own measured T0. Control is not subtracted from replay.
    fig,axes=plt.subplots(1,2,figsize=(13,5),sharey=True)
    for ax,phase in zip(axes,('idle_control','replay')):
        hr=[r for r in host if r['phase']==phase and r.get('seconds_since_phase_baseline') is not None]
        fr=[r for r in files if r['phase']==phase]
        ax.plot([r['seconds_since_phase_baseline'] for r in hr],values(hr,'cached_delta_bytes'),color=colors['host'],label='Host Cached delta')
        for key,label,color in [('lower_resident_delta_bytes','Rootfs lower delta',colors['lower']),
                                ('known_other_file_delta_bytes','Known other file-cache delta',colors['other']),
                                ('unexplained_delta_bytes','Unexplained delta (diagnostic)',colors['residual'])]:
            ax.plot([r['seconds_since_phase_baseline'] for r in fr],values(fr,key),'.-',color=color,label=label,markersize=4)
        ax.axhline(0,color='#64748b',linewidth=.6);ax.set_title(phase.replace('_',' ').title());ax.set_xlabel('Seconds from this phase baseline')
        ax.legend(fontsize=8,loc='best')
    axes[0].set_ylabel('Change in MiB');fig.suptitle('Cold-start changes: idle control versus replay',fontsize=14)
    fig.tight_layout(rect=(0,.08,1,.95))
    save(fig,'cache-delta-comparison','Host-wide Cached includes unrelated activity. Residual is not an exact accounting identity. Missing values remain gaps; no control-mean subtraction.')
    tids=sorted({r['template_id'] for r in templates});nrows=(len(tids)+1)//2
    if tids:
        fig,axs=plt.subplots(nrows,2,figsize=(13,4*nrows),squeeze=False)
        for ax,tid in zip(axs.flat,tids):
            rows=[r for r in templates if r['template_id']==tid and r['phase']=='replay']
            if not rows:ax.text(.5,.5,'No replay samples',ha='center');continue
            for key,label,color,style in [('whole_lower_host_pagecache_bytes','Full lower cache',colors['lower'],'-'),
                    ('sandbox1_accessed_and_resident_bytes','Sandbox 1 accessed + resident','#60a5fa','--'),
                    ('sandbox2_accessed_and_resident_bytes','Sandbox 2 accessed + resident','#a78bfa',':'),
                    ('accessed_resident_union_bytes','Accessed-resident union',colors['union'],'-'),
                    ('shared_accessed_host_pagecache_bytes','Common accessed-resident pages',colors['shared'],'-')]:
                ax.plot([r['seconds_since_phase_baseline'] for r in rows],values(rows,key),linestyle=style,color=color,label=label)
            ax.set_title(str(rows[0].get('trajectory') or tid),fontsize=10);ax.set_xlabel('Seconds from replay baseline');ax.set_ylabel('MiB');ax.legend(fontsize=7)
        for ax in list(axs.flat)[len(tids):]:ax.set_visible(False)
        fig.suptitle('Per-template rootfs lower cache and read overlap',fontsize=14);fig.tight_layout(rect=(0,.05,1,.95))
        save(fig,'rootfs-per-template','Full lower residency is not the same as actual-read residency. Shared layers across templates must not be summed as unique host memory.')
        fig,axs=plt.subplots(nrows,2,figsize=(13,3.6*nrows),squeeze=False)
        for ax,tid in zip(axs.flat,tids):
            rows=[r for r in templates if r['template_id']==tid and r['phase']=='replay']
            for key,label,color,style in [('shared_accessed_host_pagecache_bytes','Exact 4KiB shared-page count',colors['shared'],'-'),
                    ('coarse_256k_common_cell_capacity_upper_bound_bytes','256KiB common-cell capacity: upper bound',colors['other'],'--')]:
                ax.plot([r['seconds_since_phase_baseline'] for r in rows],values(rows,key),style,color=color,label=label)
            ax.set_title(str(rows[0].get('trajectory') or tid) if rows else tid,fontsize=10);ax.set_xlabel('Seconds from replay baseline');ax.set_ylabel('MiB');ax.legend(fontsize=7)
        for ax in list(axs.flat)[len(tids):]:ax.set_visible(False)
        fig.suptitle('Granularity check — coarse overlap is not exact shared cache',fontsize=14);fig.tight_layout(rect=(0,.05,1,.95))
        save(fig,'cache-granularity-check','256KiB cells are an aggregation comparison, not measured kernel folios. Different 4KiB pages in one cell can create coarse overlap without exact overlap.')
    manifest={'source_sha256':hashlib.sha256(raw).hexdigest(),'run_id':t.get('run_id'),
              'source_run_status':status,'accepted_source_status':accepted,
              'files':created,'synthetic_preview':synthetic_preview,'interpolated':False,'smoothed':False}
    (output/'plot-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (output/'curves.md').write_text('\n\n'.join('!['+name+']('+name+')' for name in created if name.endswith('.png'))+'\n',encoding='utf-8')
    return manifest


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('source',type=Path);ap.add_argument('output',type=Path)
    ap.add_argument('--synthetic-preview',action='store_true');args=ap.parse_args()
    print(json.dumps(render(args.source,args.output,args.synthetic_preview),indent=2))
