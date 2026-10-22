# 监督终端退出后的明确收尾恢复

适用于本提交的普通rootfs双节点v3与独立单节点入口。正常运行仍应保持协调及root终端；本入口用于原root监督进程已经退出后的特定情况，不接管旧版监督器，也不重新启动实验。

## 能够恢复的状态

原root拥有的ready回执必须绑定相同脚本SHA、scope SHA和boot。原root PID必须已不存在，新的root监督锁必须可独占；协调器、请求通道和cohort锁也必须空闲。所有请求/回执必须连续、匹配，服务启动与停止必须已有root成功回执，当前Runtime PID/start_ticks必须与最后回执一致。Guest日志须明确无沙箱、无未完成API请求；若Runtime还运行，API库存也须为空。既有其他服务身份和固定输入仍需一致。

只允许缺少回执的最后一个只读observe请求被明确记为失败，旧请求不重发。任意未确认或失败的启动／停止／provider提交、结束请求都不猜测。原PID存在或被复用、root回执版本不符、锁被占用、服务身份变化、Guest结果未知时均拒绝接管并保留证据。

恢复后的通道只允许observe、runtime-stop、finish。它不提供创建Guest、启动Runtime/provider、分配UB、强制删除对象或清除未知pins的操作。UB退役仍由原普通用户停止入口按原合同执行：先确认Guest与Runtime退出，双节点先B释放再A删除；单节点只有owner退役。恢复监督器本身不调用SDK。

## 操作顺序

先结束原普通用户协调进程，等待其退出及cohort有界收尾；不要同时运行另一个stop。保留所有回执，不修改文件所有者或手工删除请求文件。

双节点：在需要恢复的节点普通jwk终端执行（A用node-a，B用node-b）：

```bash
/usr/bin/python3 -I -B /home/jwk/agent/lazy-four-v3/lazy_four_rollout.py recovery-plan --node node-a --run
```

独立单节点：只在A普通jwk终端执行：

```bash
/usr/bin/python3 -I -B /home/jwk/agent/lazy-single-v1/lazy_four_rollout.py recovery-plan --run
```

这一步只打印固定版本的root恢复块，不开始收尾。将对应完整块放到该节点root终端执行并保持终端；必须看到`ROOT_CLEANUP_RECOVERY_READY`。随后在A普通终端执行本提交的`A_stop_retry_v3.sh`或`A_stop_single_v1.sh`，两者不可混用。

旧请求已得到合法root回复但普通客户端未记账时，只有新的runtime-stop/finish可消费该已确认回复并继续下一个序号；不会重发旧请求。没有回复时仍拒绝。恢复审计单独保存到原root拥有的`/run/agentenv-lazy-four/<nonce>/recovery-*.json`，原ready和所有操作回执保留。

## 仍需明确处理的失败

这不是通用故障接管。root在修改服务的中途退出、SDK退役回复丢失、节点重启、Guest仍活跃或创建结果未知、Runtime已异常退出但代理仍活跃，都可能超出可恢复条件。入口会停止并保留状态；不会为显示清理成功而重发不确定操作。应结合原日志逐项处理，而不是重新运行完整实验或删除未决回执。

本地检查包含真实客户端临时文件更新、实际历史重建/拒绝逻辑和监督流程模型；Linux权限、flock、systemd、SDK与目标故障场景仍未实测。该限制与可恢复条件应保留在最终报告中。
