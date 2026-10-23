import re

def need(ok,message):
    if not ok: raise RuntimeError(message)

def guest_action(run_id,mode):
    need(re.fullmatch('[0-9a-f]{32}',run_id) is not None,'Invalid run identity')
    need(mode in ('parent','check','write','private'),'Unknown Guest action')
    marker='/aenv-dsec-smoke-'+run_id
    common="set -eu; B=/agentenv/bin/busybox; test -x /agentenv/dax-check; test \"$($B id -u)\" -eq 0 || { echo DSEC_CHECK_REQUIRES_GUEST_ROOT >&2; exit 125; }; "
    dax="/agentenv/dax-check /.aenv-dax-exec; set +e; /.aenv-dax-exec; r=$?; set -e; test \"$r\" -eq 73; "
    original="test \"$($B cat /.aenv-dax-probe)\" = aenv-native-dax-v3; /agentenv/dax-check /.aenv-dax-probe; "
    if mode=='parent':
        return common+dax+original+'test ! -e '+marker+'; printf %s parent-'+run_id+' > '+marker+'; $B sync; printf DSEC_PARENT_OK'
    if mode=='check':
        return common+dax+original+'test "$( $B cat '+marker+' )" = parent-'+run_id+'; printf DSEC_RESTORE_OK'
    if mode=='write':
        return common+'printf %s private-'+run_id+' > /.aenv-dax-probe; printf %s child-'+run_id+' > '+marker+'; $B sync; printf DSEC_PRIVATE_WRITE_OK'
    return common+dax+'test "$( $B cat /.aenv-dax-probe )" = private-'+run_id+'; test "$( $B cat '+marker+' )" = child-'+run_id+'; printf DSEC_PRIVATE_READ_OK'
