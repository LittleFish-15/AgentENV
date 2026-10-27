# A 强制停止后的接续与测数顺序

本入口只用于用户已对 A 专属旧 Runtime 执行 systemctl kill/stop 后。B 不运行它。

执行文件：A_post_force_stage_deletefix_OFFLINE_root.sh，A/server1、root。
全块离线，不访问 GitHub，不重编译，不创建 Guest，不删除设备或加载模块。

1. 核旧 boot、真实 ready 回执、未确认 DELETE journal、原 provider 身份。
2. 最多观察旧 unit 30 秒，要求原进程退出、专属 cgroup 空、12/13 的 block/char 与 sysfs 均消失。若未满足，同次输出进程状态/wchan、设备身份、最多15秒常规FD持有者观察，停止且不部署。并非内核引用清零证明。
3. 只有旧资源全退出且 provider 本地许可/响应为零，才对 receipt 指定的旧 host proxy 通过 pidfd 发 SIGTERM，确认退出。不再发送旧 Runtime DELETE，不再 kill Runtime。
4. 校验已构建 daemon SHA5291c267777cd91c4b853c6d40720e8d87200b2a0162024782534c4126cba726，复用旧 server/FC/镜像/对象。在独立 agentenv-direct-ub-deletefix-v1 路径准备并激活，复用18085端口；普通用户健康和空库存通过后结束。

成功：A_POST_FORCE_DELETEFIX_HEALTHY_NO_GUEST。它只证明新服务健康，不是 Guest 验收；daemon 的实际进程/读取证据在真实 Guest 阶段采集。
失败：STOPPED_POST_FORCE_PRESERVE_STATE 或 STOPPED_POST_FORCE_PREFLIGHT。保留结果，不重跑已有部署或人工清 pending。旧两节点轮次仍是生命周期失败，不改成通过。
报告：旧部署 acceptance/direct-pair-v1/post-force-<随机ID>/report.json；如进入部署，有 prepare.log、health.log。早期路径/身份检查失败可能只有终端回执。

恢复边界：原 D1、失败 journal 和 UB 对象保留；D2 不覆盖旧产物。失败时不自动重启 D1、不恢复已退出 Guest、不释放UB；D2若健康且无Guest，可由已固定部署库 stop-empty 进行精确停止。未知库存/身份不可用该回滚。

测数顺序：修复 daemon 部署到两端 → 新两节点各1Guest正常生命周期验收 → 首模板每端2Guest、每组4Guest的真正原版/全量UB同负载对照 → 完成四模板lower覆盖与容量批准后扩为每组16Guest。小规模与16Guest分别标识。旧Host读取结果不计新对照。

当前剩余条件：本入口尚无现场执行回执；B需按既有人工方式转交唯一新daemon，B旧Guest及设备当前状态未确认；新生命周期与比较入口需要匹配D2/daemon摘要和新的验收回执，旧D1入口不得直接套用。没有获准的自动跨节点文件交换通道。
