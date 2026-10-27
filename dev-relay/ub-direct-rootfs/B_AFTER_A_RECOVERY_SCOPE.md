# 续原B Guest的A退出后读取验收

当前A单Guest修复回归已返回正常DELETE204；旧A失败轮已通过受控清理退出。保留两种退出口径，不伪造旧A正常删除回执。

B_after_A_recovery_v1.py只在B/agent1 root运行。--context为用户中转的实际A恢复与后续单机回归回执；不传输密码、私钥或私有工作负载。静态源码可发布，含实际回执的离线wrapper/context只保留本地与目标机，不发布。

核原pair/peer-isolated和原B Guest/FC PID-startTicks；若原FC已退出或PID重用，返回ORIGINAL_B_GUEST_NOT_LIVE_CONTINUITY_NOT_PROVEN，不执行命令、不新建Guest冒充原实例；同时记录旧unit/provider及已知设备状态，供后续收尾。

若原实例仍在，复用原ready/controller的真实运行链路与300/330秒语义：命令前后核FC/daemon/rootfs绑定，Guest读取原内容，必须产生同一source/trace的新UB后端请求和字节，缓存命中而无后端增量不能通过。成功ORIGINAL_B_SURVIVED_A_RECOVERY_NEW_UB_READ_PASSED。原B pair/state/phase/ready回执保持原字节，新增输出仅acceptance/direct-pair-v1/post-a-recovery-v1。无DELETE、创建、fork、快照、服务/内核改动或SDK分配/退役。

不在旧B daemon上重复已知错误的删除流程。B退出/匹配修复部署及正常生命周期另接续。若原B已超时退出，连续存活这一缺项不可补成历史成功；仅补必要的新两节点存活跨退出场景，既有写隔离证据保留。

该结果不是16Guest对照或净收益。先接完生命周期，再首模板每节点2Guest、每组4Guest原版/全量UB同负载测数，四模板覆盖/容量批准后扩16Guest。
