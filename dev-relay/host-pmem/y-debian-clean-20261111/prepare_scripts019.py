"""Build Y's manual launcher around the byte-identical live X benchmark."""
import ast,hashlib,json,pathlib
H=pathlib.Path(__file__).resolve().parent;X=H/'x-scripts019'
benchmark=(X/'benchmark_sandbox_lifecycle.py').read_bytes()
assert hashlib.sha256(benchmark).hexdigest()=='d4f5ea74fd01345dbf8df29b249bc8a4c0201a81fcbc10db4d6a5fbfcc1b30e9'
(H/'benchmark_sandbox_lifecycle019.py').write_bytes(benchmark)
run='''#!/usr/bin/env bash
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
'''
(H/'run019.sh').write_bytes(run.encode())
check=(X/'check_aenv_fc_pool.py').read_text(encoding='utf-8').replace('/data/jwk/aenv-baseline-20261103','/home/jwk/aenv-y-clean-20261111').replace('jwk-aenv-baseline-1103.service','jwk-aenv-y-clean-20261111.service').replace("'config/runtime.toml'","'config/runtime005.toml'").replace('st_uid==1000','st_uid==1002')
ast.parse(check);(H/'check_aenv_fc_pool019.py').write_bytes(check.encode())
doc='''# Y 上的 Wikidata 100 并发测试

在 root 或 jwk 终端执行：

```bash
cd /home/jwk/scripts
bash run.sh
```

默认每轮 100 并发、连续 10 轮，与 2026-11-11 实时读取的 X `/data/jwk/scripts/run.sh` 一致。核心 Python 测试脚本直接复制自 X，字节完全一致，SHA-256 为 `d4f5ea74fd01345dbf8df29b249bc8a4c0201a81fcbc10db4d6a5fbfcc1b30e9`。

脚本先做一次单沙箱 create/pause/resume/delete 预热，再测正式轮次；没有额外的 100 沙箱预热或轮间等待。pause 保留内存，SDK 为既有 e2b 2.46.0 / pyqwest 0.10.0。请求超时和沙箱生命周期沿用原 Python 脚本默认值。

只跑一轮或只检查计划：

```bash
ROUNDS=1 bash run.sh
DRY_RUN=1 bash run.sh
```

dry-run 导入真实 SDK 并写出配置和测试计划，但不调用 API、不创建沙箱。ROUNDS 支持 1..100；不传时为 10。脚本自动从自身目录寻找文件，不依赖调用时的工作目录。

结果保存在本目录 `results/e2b246-日期-时间-进程号/`，每次新建目录，不覆盖历史。主要文件为 `summary.json`、`operations.csv`、`operations.jsonl`、`config.json`、`remaining.json`。只有 `summary.json` 中 `valid=true` 才能作为完整有效结果；失败时原脚本会停止后续轮次并尝试清理。不能把失败样本的成功请求均值当作完整基线。

运行身份：root 启动时自动切换为 jwk，jwk 可直接启动。入口从本机 jwk 私有配置读取 API Key，未复制 X 的凭据。`.run.lock` 防止从此目录同时启动两份测试。

运行路径与 X 直接执行 run.sh 一样，使用宿主机 `127.0.0.1:18080` 入口。Y 的该入口由既有代理转发到服务内 Rust API。它与此前进入服务 netns 直连 Rust 的自动测试不是同一测量路径，对照时应明确区分。

`bench_image_map.json` 保留 X 的统计标签，模板 ID 指向 Y 已构建的 amd64 Wikidata 模板，规格为 2 vCPU / 4096 MiB。没有复制 X 的 ARM 模板、快照或内核。此前 Y 正式首轮 resume 曾有 20/100 连接超时，之后保持参数不变的 018 复测五轮全部通过，但 resume 延迟仍高；此入口提供与 X 一致的执行方式，不代表超时根因已确认或解决。

查看预热池：

```bash
python3 check_aenv_fc_pool.py
```

该检查读取本服务配置和 Firecracker 状态，不改参数。目录内只准备测试、映射、检查工具和说明；安装过程不启动压测。
'''
(H/'README-scripts019.md').write_bytes(doc.encode())
print('Y manual scripts prepared: default10 rounds, original live-X benchmark SHA256 retained')
