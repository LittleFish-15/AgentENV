"""Sample shared repository inodes once, retaining explicit alias evidence."""
def select_lower_views(rows,variant):
    if variant not in ('original','full'):raise ValueError('Unknown variant')
    active='rootfs-lower-original' if variant=='original' else 'rootfs-lower-ub-source'
    groups={}
    for row in rows:groups.setdefault((row['identity']['dev'],row['identity']['inode']),[]).append(row)
    selected=[];aliases=[]
    for key,values in groups.items():
        first=values[0]
        if any(row['identity']!=first['identity'] or row['contentDigest']!=first['contentDigest']
               or row['immutable'] is not True for row in values):raise ValueError('Conflicting shared lower inode identity')
        categories={row['category'] for row in values}
        if not categories<={'rootfs-lower-original','rootfs-lower-ub-source'}:raise ValueError('Unexpected lower category')
        chosen=dict(next((row for row in values if row['category']==active),first))
        if len(categories)>1:chosen['categoryAliases']=sorted(categories)
        selected.append(chosen)
        if len(categories)>1:
            aliases.append({'identityKey':list(key),'categories':sorted(categories),'paths':sorted({row['path'] for row in values}),
                            'scope':'one physical file cache, sampled under the active variant category; not two additive copies'})
    return selected,sorted(aliases,key=lambda row:row['identityKey'])
