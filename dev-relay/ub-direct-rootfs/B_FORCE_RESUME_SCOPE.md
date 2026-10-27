# 仅续做已记录的 B SIGTERM 超时

前提是原B Guest FC已不存在，新daemon文件已过ELF/SHA检查、旧upper证据已备份，原恢复仅发送SIGTERM且在90秒进程退出门控处停止；未做DEL_DEV/新部署。读取原b-deletefix-recovery-v1/progress.json，必须匹配这一准确失败状态，原目录不删除不覆盖。

B_force_resume_deletefix_OFFLINE_root.sh只B/root；执行即明确选择--allow-owned-unit-sigkill。若精确旧进程/专属cgroup仍在，先核PID/startTicks/exe/cgroup、无FC、provider不在其中、旧daemon无额外设备，再仅对jwk-aenv-direct-ub-guest-v1-node-b.service执行systemctl kill --kill-who=all --signal=SIGKILL以及stop --no-block。不是全机pkill，不触碰A或UB服务。若已自然退出则跳过强停。

30秒内需旧进程/cgroup/block均退出；否则输出state/wchan、unit和残留路径，保留未知状态，不加时或反复杀。已停止char0/1的GET_DEV_INFO/DEL_DEV、代理退出、许可归零和D2部署逻辑直接复用原固定入口，仅允许代理已经消失的情况跳过信号。旧char身份仍用原停止前major/inode/ctime，未知或重用拒绝。模块/内核/OBMM不改，UB基底不退役，新Guest不创建。

新记录位于旧PAIR/b-deletefix-force-resume-v1/progress.json；原SIGTERM失败及其upper备份保持。该恢复不能恢复旧B连续存活，也不能标正常Guest删除通过。新D2失败不自动回旧D1；若进程内核D状态无法退出，SIGKILL不能保证解决。

成功B_OLD_COHORT_RECOVERED_DELETEFIX_HEALTHY_NO_GUEST仅服务健康。后续仍需缺失的两节点退出后新UB读取与真实对照。配套测数准入已本地适配D2路径、新daemon SHA、原server来源，原版身份与300/330秒负载规则未变；完整测数入口尚未交付可运行版本。
