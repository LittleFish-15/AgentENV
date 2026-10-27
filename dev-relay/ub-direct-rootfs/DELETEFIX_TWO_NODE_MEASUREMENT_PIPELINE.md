# 两节点首模板原版／全量UB测数入口

前提：A/B的agentenv-direct-ub-deletefix-v1均已健康，当前旧B恢复完成；尚未获得B成功回执时不要启动。数据范围为首模板，每节点2Guest、每变体4Guest；真正原版与全量UB各一组，共8次测量Guest实例。四模板16Guest每组目标仍未完成，扩容/覆盖单列，不混写。

## 执行路径与最少人工中转

本地私有A_start_deletefix_measurement_pipeline_OFFLINE_root.sh带已返回的历史写隔离回执，不发布它；公开的AB_deletefix_measurement_pipeline_v1.py只含通用代码与固定组件。人工按打印出的完整命令交接，不新增SSH/端口或固定sleep协调。

1. A/root运行私有启动块：核D2、用完整201→204/退出证据收尾已完成smoke的空active标记，创建一个新Guest并核实际UB读。打印NEXT_B_COMMAND。
2. B/root执行该块：创建新B Guest并核同对象/代次和实际读，打印NEXT_A_COMMAND。
3. A/root执行该块：单次普通DELETE，核FC、私有block/char/sysfs、memory引用、UB许可释放，打印NEXT_B_COMMAND。
4. B/root执行该块：核A正常退出回执，要求B新后端读和原内容，再正常释放B。完整验收通过后，先打印NEXT_A_ORIGINAL_COMMAND，再自动开始B原版两Guest回放与采集。
5. A/root执行A原版命令，可与B原版在各自已有终端并行。两端原版各完成后，分别打印对端的FULL命令。
6. 等两端均出现原版LOCAL_COMPARISON_PHASE_RELEASED，再执行A_FULL及B_FULL命令。入口同时核本地原版完成和对端原版原始回执；提前执行不会越过门控。
7. 每端full完成后，保存jwk可读的独立node-package JSON，返回路径/字节数/SHA。两包回本地后做离线整体核对和简明对照，不需要再次跑实验。

理想成功路径共7次终端命令：Aready、Bready、Aexit、Bfinish+自动Boriginal、Aoriginal、Afull、Bfull。4个配对命令仅验证缺失的跨退出场景；不重跑历史A私有写/B基底全文核验。实际执行由人中转，阶段起点不保证同步，不宣称同时窗驻留交并或整集群同一时刻峰值。

为避免B续验只命中Host ublk缓存，第4步在读取计数基线之前对已确认属于该Guest的私有rootfs设备做一次BLKFLSBUF（同步并失效该设备缓存），然后再取trace基线并执行既有Guest O_DIRECT读取。只作用验证Guest的私有rootfs，不碰memory设备、其他Guest或全机cache；有独立意图和内核操作成功回执，失败停留，不全机清缓存或反复尝试。两个正式测量变体均不执行此操作。

## 版本和证据

全量server仍为ff1构建的759423e6，daemon为d97删除修复的5291c267；各进程PID/startTicks/exe/inode及文件摘要实读。真正原版为ae9c626的既有server/daemon/CLI，不能用修改版关UB冒充。实际Guest lower配置、FC持有rootfs设备、UBLK256KiB队列与全量真实UB事件都核验；原版lower必须实际引用计量的普通文件inode。

写隔离证据来自旧ca0e30a3轮；新正常退出对来自e846ecf5轮，明确多轮证据组合，旧A失败DELETE不改成通过；收益测量全部来自新的9c8f00d9轮。按对象/代次/内容/模板绑定对齐，两端实际读取和普通DELETE ACK缺一不进入测数。

## 采集和结果

每组2Guest执行相同已冻结回放，记录每条命令摘要、退出码、延迟、耗时；Guest300秒/CLI330秒不变，非零退出保留并逐项对比，超时/未知/采样失败不当成功。无全机drop_caches、无普通lower payload预读或隐式本地回退。

采集沿用1秒进程/Host与约15秒文件/设备/GuestRAM观察，保存创建前、回放前、结束释放前三个边界。控制台MEASUREMENT_PROGRESS显示实际已完成/预期命令数；每阶段成功立即打印缓存增量、分项文件驻留、进程PSS、耗时及唯一UB保留量。

UB账由A当前provider映射与export sysfs元数据生成，19个128MiB区域只算一次，明确“报告的保留容量”，不冒充独立增量物理计费。B的import映射不重复计成第二份。原版期间保留此池，背景占用不隐藏。

原版和UB源仓库若为同一inode的硬链接，记录别名并按当前变体只采一次，不能重复相加；不同inode分别采。对照明确初始缓存状态和顺序效应，不把未回收的旧缓存说成已经释放。

指标分开：Host Cached、各类普通文件cache、UB保留容量、进程PSS、GuestRAM与设备cache可能重叠，禁止简单相加。瞬态CLI成本和部分索引归因仍不足，整体净收益保留NA；可以交付真实缓存分项差值、UB成本、辅助进程变化与性能差异，负数如实。不能将这轮结果写成16Guest、原子全局总量或正净收益已经实现。

## 失败与保留

每个POST/DELETE/阶段意图均落盘；未知结果不凭空库存清除，不自动重试或清理失败Guest。重复阶段目录/非静止journal会拒绝。原始命令stdout/stderr与samples.jsonl留在各节点D2/comparison/deletefix-full-v1；数据包位于/home/jwk/agent/deletefix-comparison-9c8f00d962c848c4b07e089bd69c5476-{a,b}.json，归jwk。

只释放本次正常完成的Guest和私有rootfs设备；memory池可按既有策略换占位镜像保留并记账；共享UB基底/provider继续保留供复测与后续四模板，不自动退役。模块、OBMM、内核、原服务、报告会话均不修改。

当前状态：本地构建/合同检查完成不等于现场通过；本文件及入口不包含任何新实机收益结果。
