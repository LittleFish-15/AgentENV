# Native单节点／两节点统一候选入口

`native_archive_round.py run-a --scenario single-a|dual-ab --run`在A由普通实验用户执行，负责固定helper安装、复用或构建新版Runtime、provider准备、独立Runtime部署、A捕获、私有快照传递、回放、停止与退役。需要root操作时打印该节点的完整固定块；用户执行后，入口观察真实状态继续，不要求手工传脚本或粘贴SDK日志。

**这是native候选的功能和数据入口，不是已经完成硬件验收的完整跨节点CoW产品。memfile真正私有CoW未实现。** Guest DAX的数据访问、可执行映射与KVM行为仍须现场通过；若失败，记录失败并按有证据的资源状态收尾。完整物理净收益不预设正值，也不会用SDK覆盖代替。

## 执行前已有制品

入口首先读取并验证已有四模板native raw准备回执：`builds/native-four-inputs-v1/return.json`。必须是完整ready，四个raw镜像及sourceConfig内容与回执一致。当前尚未收到足以确认此准备已完成的实机回执；若缺失或不完整，入口在SDK和服务启动前停止，**不会自动重新导出、复制64GiB原盘或重做压缩**。

还需要已有`builds/native-four-release-v1/return.json`及相邻五个二进制、`r/pm-a-v1/tools-runtime/return.json`及对应tools文件、旧已释放lazy-v1的SDK适配器与释放回执。server/daemon使用5e6621c：`builds/content-observer-release-v2/return.json`若完整则复用；目录完全不存在才运行固定离线builder一次，partial目录拒绝重做。FC/verifier/CLI明确复用32ce构建，不重新编译。

双节点使用用户此前配置的jwk专用SSH密钥和known_hosts；不创建密钥、不改SSH配置或全局用户组。原版服务须健康，新native场景目录不能已有或残留。普通c560对照与native场景不能并行运行；未知旧引用不自动释放。

## 最少操作形式

1. A普通用户启动一个对应场景的入口，保持该终端。
2. 按输出在对应root终端执行固定块。每节点通常三次：provider提交、新Runtime启动、空闲Runtime停止。provider采用显式detached提交，root终端会返回；这不代表SDKready。入口随后检查owner serving与精确unit，停止后再检查旧进程已消失。
3. 全部结束后读取该场景工作目录的`comparison.json`、`comparison.md`和`cleanup.json`。保留失败报告及日志，不从头重跑已有目录。

```sh
# 严格A-only：四模板×每模板两个Guest，B不接触、不导入
python3 -I -B native_archive_round.py run-a --scenario single-a --run

# 两节点：每节点四模板×每模板两个Guest，恢复同一组A快照
python3 -I -B native_archive_round.py run-a --scenario dual-ab --run
```

单节点使用`native-archive-single-*`目录和独立代际；双节点使用`native-archive-*`，不会以“B有空闲映射”充当严格单节点。默认每模板两次restore；如明确选择`--replica-mode restore-fork`，则每模板一次restore和一次实际Fork，报告会区分。创建顺序不是并发Fork压力验收。已有场景目录不因改变replica-mode而覆盖。

单节点不发起任何B连接。双节点先确认A/B provider，再启动A Runtime、捕获四个parent并释放；将VM state、memory/rootfs层和native原始归档私下传到B，B在尚未启动时校验/播种新仓库，随后启动并恢复A的同一组ID。两端通过独立admission/completed屏障采样，不宣称指令级同步。

## 输出及解释

| 场景 | A工作目录 |
|---|---|
| single-a | `r/native-archive-single-rollout-v1` |
| dual-ab | `r/native-archive-rollout-v1` |

工作目录含阶段journal、完整logs、捕获／逐节点回放报告、双节点屏障、cleanup、JSON/Markdown汇总。业务原始samples和每步命令输出还保留在对应部署的`native-cohort/<scenario>-<replica-mode>/`。

报告保留逐模板/slot/step的实际退出码、任务时间、失败或超时、4GiB实际Guest RAM VMA、整FC、Host/PSI、private upper、Runtime/provider charge和辅助进程。native观察器已纠正旧512MiB尺寸假设，仍用FC API区间与smaps核对；不能用大小猜VMA。辅助采集限定collector、匹配命令的父coordinator及精确Runtime host proxy，缺项NA；SSH及kernel/driver开销未穷尽。

UB按ownerId归组，owner覆盖只记录一次，保留各节点观察，不把A/B同对象覆盖相加。覆盖仍不是物理增量。Guest文件缓存包含在Guest RAM中，尚无完整独立归因；DAX逐文件完整访问集合／驻留物理计量和整体净节省为NA。

本native入口没有重新跑原版Runtime。已有原版数据只作历史参考；`completeCounterfactualAccepted=false`。必须匹配逐命令结果、环境与不重复的内存账目，才能接受完整原版／新版收益结论。普通rootfs缓存的同版本off/lazy对照继续用c56082c单／双入口；其off也不是ae9原版。

## 成功、失败和恢复边界

`NATIVE_ROUND_MEASURED_AND_RELEASED`表示候选回放完成、已知Guest释放、对应Runtime及proxy退出、B/A provider有精确释放／删除／finalize证据且进程退出。它不等于memfile CoW完成或正收益。

回放、控制通道或SDK失败时，入口仍尝试按原case journal对已知Guest收尾。只有全空且无unknown，才打印Runtime停止块；provider按B释放收据→A退役执行。退役命令最多发送一次，丢回复后只观察journal；不靠重发、超时或进程死亡推断释放。

无法证明的状态记录`NATIVE_CLEANUP_STOPPED_PRESERVE_UNKNOWN`并保留。例如B SDK初始化/导入失败，缺少对应代际的释放证明时，A预登记B reader的对象不能擅自删除。用户未执行provider root块时，单凭输出目录不存在也不能推断从未启动。此版本不承诺任意故障自动清理，不支持盲目重跑已有场景；保留报告后再根据明确状态恢复。

默认不带`--run`仅打印计划，无Host访问或改动。夜间开发未连接两台机器、未启动SDK或Guest。脚本通过本地编译与模型/文件集成检查；Linux部署、KVM/DAX和真实收益留待用户现场验收。

本地186项交付检查通过，包括单节点禁止B操作、双节点阶段顺序、capture失败进入收尾、未知状态不退役、唯一owner覆盖不重复计、4GiB RAM绑定和helper版本闭合。模型执行不能代替目标部署或硬件验收。
