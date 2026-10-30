"""Pre-START attribution contract for a separately reserved experiment group.

The caller must reserve the group, keep its membership empty, launch only the
owned Runtime with that primary GID, and verify all holders on every check.
This module does not create groups, grant permissions or delete devices.
"""

def attribute(info, *, reserved_gid, owned_units, processes, group_members,
              scan_complete, executable_hashes):
    if not scan_complete or group_members or reserved_gid in (0,1205):
        raise ValueError('Dedicated group isolation not established')
    if info['uid']!=1204 or info['gid']!=reserved_gid:
        return None
    members=[p for p in processes if reserved_gid in p['allGids']]
    if not members:
        raise ValueError('Dedicated group has no verified live owner')
    for p in members:
        if (not p['stable'] or p['uids']!=[1204]*4 or p['unit'] not in owned_units
                or p['unitIdentity']!=owned_units[p['unit']]):
            raise ValueError('Dedicated group escaped the experiment')
    daemons=[p for p in members if p['primaryGid']==reserved_gid
             and p['executableSha256'] in executable_hashes]
    if len(daemons)!=1:
        raise ValueError('Expected exactly one attributable daemon')
    owner=daemons[0]
    if info['pid']==-1:
        if info['state']!=0:raise ValueError('Unstarted PID in unexpected state')
    elif info['pid']!=owner['pid']:
        raise ValueError('Started device daemon differs')
    return {'pid':owner['pid'],'ticks':owner['ticks'],'unit':owner['unit'],
            'kernelOwnerGid':reserved_gid,'kernelPidKnown':info['pid']>0}
