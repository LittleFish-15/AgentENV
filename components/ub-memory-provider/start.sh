#!/usr/bin/env bash
# Native demand debug entry. Default checks only; never touches full-mode state.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$here/../.." && pwd -P)
action=${1:-check}
python=${AENV_DEMAND_PYTHON:-python3}
case "$action" in
  prepare)
    shift
    exec "$python" -I -B -c 'import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module("aenv_ub_provider.demand_catalog",run_name="__main__")' "$here" "$@"
    ;;
  check)
    "$python" -I -B -c 'import sys; assert sys.version_info >= (3,11), "Python >=3.11 required"'
    (cd "$here" && "$python" -B -m unittest discover -s tests)
    if [[ -n ${AENV_DEMAND_CONFIG:-} ]]; then
      exec "$python" -I -B -c 'import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module("aenv_ub_provider.demand_runtime",run_name="__main__")' "$here" validate --config "$AENV_DEMAND_CONFIG"
    fi
    printf '%s\n' DEMAND_LOCAL_CHECKS_ONLY_NO_SDK_NO_DEPLOYMENT
    ;;
  build)
    [[ $(uname -s) == Linux ]] || { echo 'Native Linux build required'; exit 1; }
    [[ $(id -u) != 0 ]] || { echo 'Build as ordinary user'; exit 1; }
    export CARGO_TARGET_DIR=${AENV_DEMAND_TARGET_DIR:-"$repo/target-demand"}
    cd "$repo"
    cargo build --locked --release --bin server -p agentenv
    cargo build --locked --release -p uvm-ublk-daemon
    sha256sum "$CARGO_TARGET_DIR/release/server" "$CARGO_TARGET_DIR/release/uvm-ublk-daemon"
    printf '%s\n' DEMAND_BINARIES_BUILT_NOT_DEPLOYED
    ;;
  validate|serve|status|drain|close-admission|finish)
    : "${AENV_DEMAND_CONFIG:?Set absolute private role configuration path}"
    exec "$python" -I -B -c 'import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module("aenv_ub_provider.demand_runtime",run_name="__main__")' "$here" "$action" --config "$AENV_DEMAND_CONFIG"
    ;;
  *) echo 'Usage: start.sh [check|prepare|build|validate|serve|status|drain|close-admission|finish]'; exit 2 ;;
esac
