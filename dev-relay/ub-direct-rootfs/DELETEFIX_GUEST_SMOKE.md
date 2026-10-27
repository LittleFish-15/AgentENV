# 修复版 A 单Guest正常删除回归

A/server1、root执行A_deletefix_real_guest_smoke_OFFLINE_root.sh。仅当前已健康D2服务，固定server PID85472/start86348532，daemon SHA5291c267...；不会重编译、部署、重启服务或调用内核删除辅助程序。固定恢复同一首模板，最多1Guest，要求8个lower必需UB绑定与该Guest真实后端事件。

复用原ready/controller逐字源码，显式绑定新D2、独立acceptance/deletefix-smoke-v1、固定新runId；Guest命令300秒、CLI330秒保持。创建/命令失败保留原journal，不自动清理。读取通过后单次普通Runtime DELETE，保存真实HTTP响应；只有200/204、FC退出、私有rootfs block/char/sysfs消失、local UB permits/payload为0、库存和journal空才通过。共享memory设备必须消失，或有本次删除后同设备refcount0与已换占位镜像回池的日志；池成本另列。

成功状态A_DELETEFIX_REAL_GUEST_READ_AND_NORMAL_DELETE_PASSED。只证明A修复版单Guest回归，不代表两节点写隔离/peer退出后读取/规模比较或正收益。失败STOPPED_DELETEFIX_GUEST_SMOKE_PRESERVE_STATE，保留smoke-report.json、delete-api-response.json、原state/trace及Guest；不可重跑已有目录。

输出目录/home/jwk/agent/deployments/agentenv-direct-ub-deletefix-v1/acceptance/deletefix-smoke-v1。共享UB基底、provider和D2服务均保留。原旧失败轮journal不修改。B尚需接入同一daemon版本和正常生命周期；B仅需从A已构建产物人工转交新daemon到/home/jwk/agent/uvm-ublk-daemon-private-delete-v1，jwk所有，不复制server/镜像/rootfs。
