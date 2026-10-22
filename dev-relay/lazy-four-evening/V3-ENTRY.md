# 四模板两节点 v3：统一构建、部署、对照、采集与收尾

核心源码版本：`5e6621c9c9d2e347959a61a46c7f6d99688eeb55`。协调发布使用Runtime/daemon编译源`5e6621c9c9d2e347959a61a46c7f6d99688eeb55`与提供者Python源`2f1550f`；本版Runtime包含读取在途计数和pmem POSIX持久化修复，provider Python字节仍与固定2f版本一致，SDK适配器继续复用。新的Runtime/daemon必须使用builds/content-observer-release-v2；只有同源成功构建才复用，旧v1构建保留。入口包含20个按SHA固定的帮助模块和离线源包。已完成代码接合与本地131项检查；尚未在目标节点执行新版本构建、部署、SDK或Guest验收，不保证通过或正收益。

## 实际测试范围

A/B每节点4模板、每模板2个Guest，每轮16 Guest，回放每节点382条相同动作。先运行同一新二进制的UB关闭轮，再运行UB按需rootfs缓存轮。它不是ae9原版二进制对照，也不是独立的单节点试验；旧单节点数据只作背景，不能直接相减。Guest任务300秒、CLI330秒不放宽；逐命令退出码必须匹配，超时不忽略。

这条入口验证普通OverlayBD/ublk路径的rootfs按需UB缓存，Guest仍有自己的文件缓存。memfile跨节点私有CoW尚未实现；native pmem/Guest DAX业务快照生命周期不由这条普通块路径入口验收。核心已包含pmem持久制品实现，但启用和硬件验收是另一个明确阶段。

## 最少现场步骤

1. A普通jwk终端执行同提交的`A_run_retry_v3.sh`。它通过官方Git Data blob接口读取固定源码，校验Git对象及SHA256。保留此终端。
2. 入口验证旧实验完整释放及当前安装，等待已有准备锁，复用成功的固定构建；若尚未构建，自动使用现有离线依赖构建新server和观察daemon。不会重新下载镜像、重建FC或调用SDK。失败/部分构建保留，不自动重做。随后仅将候选二进制和回执通过已配置的jwk SSH传给B，隔离安装。
3. 看到打印的两个root块后，在A/root和B/root各执行对应完整块一次，并保持终端。接下来的启动、两轮回放、报告与收尾由A协调入口执行。不要提前关闭root监督终端。

新版二进制/启动器/config/definition/receipt放入原部署目录内的`libexec/observed-v3`，不覆盖原安装。目录名仍含32ce以复用原镜像、快照及依赖；实际运行版本以新coreCommit和binaryPins为准。每个daemon的日志使用独立PID文件名，固定观察spec绑定真实lower inode与内容摘要。

## 结果与统计边界

A统一结果目录：`/home/jwk/agent/r/lazy-four-rollout-v3`。完整报告位于`comparison/comparison.json`和`comparison/comparison.md`；失败轮尽量生成`partial-comparison`，另保留`return.json`、`cleanup.json`、逐phase日志和节点原始报告。节点原始回放、样本和命令日志在保留部署目录的`four-cohort-v3/off`及`four-cohort-v3/lazy`。

报告保留实际Guest RAM VMA、整FC、upper、Host、provider、UB唯一池等原有分项；缺项NA，不相加重叠指标。新增完成屏障内的读取/驻留证据：逐sandbox读取范围、普通文件mincore有效内容范围、A的单一UB ready集合、每节点与跨节点逻辑交并及逐模板交集。两节点各自冻结任务读取集合，使用同一完成屏障，不能直接比较不同节点的monotonic数值。

观察器日志按固定PID、构建标识、序号和状态计数校验。当前接受的是状态所确认的日志前缀，新版状态提供已接入观察器读取的在途完成确认；采集最多等待10秒并核对前缀字节数，确认结果单列。但这不覆盖Guest文件缓存命中或所有未接入路径，因此`fullAccessCoverageAccepted=false`；不得把已观察集合称为穷尽读取。未取得有效前缀/绑定/采样时明确NA，不用完整lower驻留替代实际访问交集。普通文件尾页的page bytes与有效内容bytes分开。观察日志cache和cohort进程开销保留，可能与Host/cgroup重叠，不能重复相加。

仅对自己的保留lower文件作既有scoped advice，不做全机drop_caches。清理后的非零驻留作为实测基线保留；不再要求绝对零，也不宣称严格冷态。完整任务/退出码匹配不等于背景隔离或性能因果验收。UB ready内容、SDK覆盖、逻辑池容量均不冒充物理增量，物理净收益仍NA。

## 停止与恢复

若A协调入口已退出且root监督终端仍在，执行同提交`A_stop_retry_v3.sh`。协调锁防止并发收尾；按确认Guest退出、停本实验Runtime/proxy、B先释放、A后释放/删除、关闭root监督与metadata传输的次序处理。未知回执/未知pin保留，绝不超时推断释放。以cleanup与return回执为准，终端退出本身不是释放证明。

旧安装文件未被替换，停止新版后无需回写旧文件，也不会自动重启其他服务。构建输出、镜像、快照、日志及回执保留。root监督通道若意外中断，收尾可能保留未决状态；入口不会绕过身份和引用核验强制清理。构建/安装前失败尚未创建Guest或UB对象，不应为此执行SDK删除。

新版进程回执使用独立的`runtime-attestation-observed-v3.json`，首次启动不会把旧二进制的回执当作新版回执，也不会覆盖它。完整访问集合的穷尽值保留NA；数值交并仅指已验证日志前缀中的集合。

提供者显式配置`maxConcurrentReads=4`（通用组件默认1，上限8）。它重叠独立元数据等待，每个读取仍持有有效pin直至映射读取结束并确认释放；退出前拒绝任何active read，未知回执不自动恢复或释放。现场会在SDK启动前执行改动相关的Python并发/生命周期/观测协议检查，使用模拟映射，不冒称UB穿刺。报告保留配置、实际流水线峰值与排队次数，SDK互斥的NC拷贝仍串行，不能承诺提速。

回放准入核验隔离安装的installation.json及新server/daemon，CLI仍复用旧已核验字节。新receipt明确runtimeSourceCommit；旧receipt和旧bin不参与新版server/daemon来源判定。实际cohort来源校验代码与stage产物联测通过，混入旧daemon或旧来源字段会被拒绝。

新增受限的root监督恢复，操作见同提交RECOVERY-ENTRY.md。仅接管相同boot/script/scope且连续确认、无Guest/未决意图、当前服务身份一致的状态；只允许观察与收尾，不恢复新实验启动。无法确认的服务操作或SDK退役继续保留。监督器白名单显式包含本版observed_io.py，其他任意帮助文件仍拒绝。

新版协调构建包含原始归档文件测试、provider协议测试、11项Linux观察器源码测试、POSIX native归档发布测试和server/daemon构建五个阶段，必须全部成功才stage。任务300/330秒不变；等待读取完成确认发生在任务结束、Guest仍保持的采集阶段，确认缺失保持前缀范围与NA，不伪造全部访问覆盖。
