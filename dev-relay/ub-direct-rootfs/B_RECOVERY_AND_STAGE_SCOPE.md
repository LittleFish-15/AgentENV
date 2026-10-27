# B原Guest已退出后的定范围收尾与修复版部署

前置：用户先将A已构建uvm-ublk-daemon传到B的/home/jwk/agent/uvm-ublk-daemon-private-delete-v1，jwk所有/单链接/不可组或其他写，24758576字节，SHA5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726。入口在任何停止动作前核ELF/长度/SHA和已有server、8GiB磁盘余量。文件缺失拒绝执行，不把服务停下再等传输。

节点仅B/agent1，固定boot e5aaa223-c78c-4eac-816e-7d98e0cca1c1。读取已返回的post-a-recovery-v1/result.json及原peer-isolated journal。旧server必须2723514/start62254196，daemon2723962/start62254283，原FC不在且没有其他FC；daemon实际仅持有由原SID日志确认的0/1设备，provider不在旧unit内。

只给精确pidfd旧Runtime主进程SIGTERM，按既有服务关闭流程等待最多90秒；不显式SIGKILL、不发旧Guest DELETE。进程/cgroup未退出、provider仍有本地许可时停止，保留progress。退出后若block与char都消失则无需辅助清理；若只剩0/1的char，需与停止前捕获的major/inode/ctime完全一致，辅助程序GET_DEV_INFO要求DEAD/-1/uid1204/gid1205才单次DEL_DEV。helper仅接受B/boot/0或1及旧PID均不在；不加载模块、不改内核/OBMM/内存拓扑。两端UB对象和provider保留，A不操作。

只有旧设备、旧代理、旧本地许可全部退出后才复用已在A通过的AB_deploy_direct_deletefix_v2，在B独立agentenv-direct-ub-deletefix-v1准备/启动。同18085端口，server/FC/镜像/8对象复用，仅daemon换为已在A正常DELETE204验证的产物。普通用户health/空库存成功为B_OLD_COHORT_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST，不宣称B Guest或两节点验收通过。

记录在旧D1 acceptance/direct-pair-v1/b-deletefix-recovery-v1/progress.json及prepare.log/health.log/可选helper日志。存在该目录拒绝重跑；原journal不改写。现存upper/config在预算内保留证据，已经缺失记NA；不是可恢复VM快照。旧Guest已退出，收尾无法恢复其连续存活历史。旧设备登记删除不可逆；新D2失败保留日志，不自动重启D1。新D2空服务的精确停止仍由固定部署库stop-empty执行，未知库存不得使用。

发布只含源码、固定辅助产物和公开环境标识，不含私有负载或现场报告。helper为本地ARM64交叉构建；B原生内核API/服务退出仍待现场回执。后继只补缺失的两节点存活跨退出场景，再首模板4Guest/组原版全量对照；16Guest覆盖/容量目标保留。
