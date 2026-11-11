#!/usr/bin/env bash
set +x
set -euo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $(id -u) == 0 ]]; then
  exec runuser -u jwk -- env ROUNDS="${ROUNDS:-10}" DRY_RUN="${DRY_RUN:-0}" bash "$SCRIPT_DIR/run.sh" "$@"
fi
[[ $(id -u) == 1002 ]] || { echo 'Run as jwk or root.' >&2; exit 2; }
[[ $# == 0 ]] || { echo 'Use ROUNDS=1 bash run.sh; positional arguments are unsupported.' >&2; exit 2; }
ROUNDS=${ROUNDS:-10}
[[ $ROUNDS =~ ^[1-9][0-9]*$ ]] && (( ROUNDS <= 100 )) || { echo 'ROUNDS must be 1..100.' >&2; exit 2; }
[[ ${DRY_RUN:-0} == 0 || ${DRY_RUN:-0} == 1 ]] || { echo 'DRY_RUN must be 0 or 1.' >&2; exit 2; }
exec 9>"$SCRIPT_DIR/.run.lock"
flock -n 9 || { echo 'A test from this scripts directory is already running.' >&2; exit 1; }
unset PYTHONPATH PYTHONHOME
export PYTHONNOUSERSITE=1
export E2B_API_KEY="$(< /home/jwk/aenv-y-clean-20261111/config/api-key)"
export NO_PROXY="localhost,127.0.0.1${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"
extra=()
if [[ ${DRY_RUN:-0} == 1 ]]; then extra+=(--dry-run); fi
exec /home/jwk/aenv-y-clean-20261111/sdk/g4-e2b246/bin/python -B "$SCRIPT_DIR/benchmark_sandbox_lifecycle.py" --api-url http://127.0.0.1:18080 --total 100 --batch-size 100 --rounds "$ROUNDS" --image-map "$SCRIPT_DIR/bench_image_map.json" --output-dir "$SCRIPT_DIR/results/e2b246-$(date +%Y%m%d-%H%M%S)-$$" "${extra[@]}"
