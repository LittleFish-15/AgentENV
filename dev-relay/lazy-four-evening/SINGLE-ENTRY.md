# 四模板独立单节点对照入口

仅在 A 运行四模板、每模板两个沙箱，共8沙箱/382条回放动作。先同一修改版关闭UB，再开启单个256MiB按需rootfs缓存池；池只注册owner，没有B导入者、不启动B服务或SSH连接。任务语义保持Guest300秒、CLI330秒；不同退出码、超时、未释放Guest均拒绝完整同负载验收。

这是普通OverlayBD/ublk路径的rootfs缓存对照。Guest仍有私有文件缓存，memfile跨节点私有CoW未实现。本入口不验收native pmem/DAX，也不是ae9原版二进制对照。不会将两节点试验的A节点切片称为独立单节点数据。

Runtime/daemon源固定为6ab53dd2e1f33cb63cbad63eb62a3388494e382c；provider Python固定为2f1550f826d858e9a230cd28a8386c2028ab225b，并发准入显式4。两者间Rust/SDK未改。复用同一成功构建、现有镜像/快照/adapter/catalog；只有此前没有成功构建时才构建server/daemon。没有重复编译FC、下载业务镜像或改变原安装。

## 现场步骤

1. A普通jwk执行同提交的`A_run_single_v1.sh`，保持终端。入口下载固定Git blob，校验对象ID/SHA256/长度，安装19个固定帮助模块。
2. 打印A/root完整块后，在A/root执行一次并保持终端。之后启动、两轮回放、报告、Runtime停止、owner退役和root监督结束自动协调。B无需操作。

单节点与两节点流程应顺序执行，不并行。两者使用同一个准备锁、Runtime服务名、镜像库和cohort锁，独立安装路径与试验目录；未知活跃/未确认释放的provider代际保留并停止准入。旧现场已确认清理，不再次清理它。

单节点新版安装在原部署目录`libexec/observed-single-v1`，实际server/daemon、config/installation及runtime-attestation使用此代际；旧CLI复用。运行目录为`/home/jwk/agent/r/lazy-single-v1`，provider目录为`r/lazy4-a-single-v1`。原安装字节保留。已有不同入口/半成品/回执不会覆盖；不把重新运行当作恢复。

## 结果

统一目录`/home/jwk/agent/r/lazy-single-v1`：`comparison/comparison.json`与`comparison.md`、`return.json`、`cleanup.json`、阶段日志。失败轮尽量生成`partial-comparison`。原始逐命令、样本、生命周期日志保留在部署目录的`four-cohort-single-v1/off`和`lazy`。

报告包含实际任务结果/耗时、实际Guest RAM VMA与整FC、私有upper、Host、provider/cgroup、唯一UB池计数，以及每模板两Guest已观察读取前缀与完成时驻留集合的交并。完整lower驻留与实际观察到的访问集合分别列示。尚无终止排空证明，穷尽访问字段为NA；未知物理增量与净收益也为NA。UB预算模型不是实测净内存收益，缺失指标不写0。

每模板交集不能相加当全局唯一字节；全局至少两Guest共同内容另算。RAM VMA属于整FC，PSS/cgroup/Host/UB映射也可能重叠，不能直接相加。独立单节点与两节点结果可分别报告，但不同节点总数、任务数和背景负载仍须注明，不能直接拿绝对缓存差当新增收益。off是相同修改版关闭UB；历史ae9原版数据仅作参考。

## 停止与恢复边界

中断A普通协调进程后，保持root监督终端；协调进程会尝试有界收尾。确认该协调进程已退出后，可执行同提交`A_stop_single_v1.sh`：它通过原回执确认自己Guest已释放/Runtime已停，再请求本代际owner退役，最后结束监督。不会连接B、释放未知pins、删除别人的对象、全机清缓存或覆盖旧证据。

若root监督通道提前关闭，或SDK/Guest结果仍未知，入口保留回执并拒绝声称清理完成；本版仅支持RECOVERY-ENTRY.md列明的已确认状态接管；未知服务或Guest结果仍需根据证据处理，不能直接重复run-a。成功收尾只停止本试验新服务并释放本试验新UB对象；保留二进制、快照、源码、日志和报告，无需回拷旧安装文件。

本地12项单节点检查及全体127项交付回归通过，覆盖实际入口流程模型、owner-only清单、固定帮助模块、版本路径、失败收尾、逐命令比较、集合去重/错误窗口NA及默认plan不动作。Linux/systemd/SDK/KVM/真实Guest尚未执行，不保证现场通过、提速或正收益。
