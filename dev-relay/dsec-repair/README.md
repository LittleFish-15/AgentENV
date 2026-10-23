# DSec Runtime pmem ID 修复与真实模板验证

此入口用于已经部署并报告健康的 A 节点实验 Runtime。它针对一次已知的冷启动失败：Runtime 把含连字符的 pmem ID 发给 Firecracker，资源 ID 检查拒绝该请求。

核心修复固定为 `268104ecc65080d776c2301e09e7902686ac4253`。只改变新建 pmem 设备的资源 ID，保留设备顺序和已有快照内容引用；没有放宽 Firecracker 的校验。现有 Firecracker、FD verifier、CLI、ublk daemon、工具和四模板镜像继续复用，各自来源仍记录为原构建版本。

构建只替换一份已发布源码，完整核对864个原文件，保留原源目录。新的server在其rustc包装进程退出前从唯一链接产物复制到私有制品目录，再让Cargo退出；不把共享构建目录里的通用`release/server`路径当作版本来源，避免其他构建后来覆盖该路径。此包装器和安装门槛经过本地解析/文件测试，仍须A的原生构建确认。

## 三个阶段

1. **普通用户 `prepare`**：构建或复用修复后的 server，校验完整源文件清单和原制品，核对唯一失败请求与指定沙箱。若该沙箱仍存在，只在 metadata 与本轮匹配且没有其他沙箱时记录删除意图并删除一次。原 pending 不在此阶段清除。准备旧文件备份、候选文件及完整哈希，打印一次 root 命令。
2. **root 执行打印的固定命令**：再次核对文件、进程和空库存，停止本任务的旧实验 Runtime、文件 provider 与 Host proxy，并确认进程/cgroup退出；随后才解析原失败请求、替换 server 及相关安装元数据、启动新版本并检查健康。原版及其他服务不执行停止、重启或配置修改。失败时保存阶段记录。
3. **普通用户 `validate`**：使用新进程的激活证据运行第一个真实模板。一次父沙箱、一个快照、两个恢复子沙箱，最多同时两个 Guest；检查 DAX、基础镜像程序执行、upper 快照持久化和私有 copy-up 隔离。结束清理已登记 Guest，保留快照和日志。

在 A 的 `/home/jwk/agent` 使用同一个已校验入口：

```text
python3 -I -B A_dsec_repair_and_validate_v1.py prepare
# 在 root 终端执行 prepare 打印的完整命令
python3 -I -B A_dsec_repair_and_validate_v1.py validate
```

不得跳过 root 阶段直接测试，也不要重复旧 v1 smoke 的 run。`prepare` 遇到已完成的暂存计划会复核并重新打印相同范围的 root 命令，不重复编译或创建 Guest；不完整的暂存和未知请求会保留并停止。

## 状态、日志与恢复

- 修复构建：`builds/dsec-pmem-id-fix-v1/return.json` 及同目录阶段日志。
- 更新暂存：`deployments/agentenv-dsec-hostfile-v1/updates/pmem-id-fix-v1/`。
- 更新状态：上述目录 `root-state.json`、`swap-state.json`、`retirement-proof.json`、`activation-proof.json`。
- 新验证报告：`deployments/agentenv-dsec-hostfile-v1/dsec-real-template-smoke-v2/return.json`；命令日志和已脱敏 API 错误同目录保留。
- 旧失败 smoke v1 的日志、state 和所有镜像/快照保留。

普通用户执行入口的 `status` 查看本地状态和固定范围的 root 恢复命令。若验证已创建 Guest 或有未确认请求，先运行同一入口的 `recover`，它只处理登记的自有对象，不新建 Guest。未知 POST 不会因库存为空而被自动清除。

root `rollback` 只接受本次更新的已知文件版本。健康候选必须无 Guest、无 pending，并验证进程身份后才会停止；安装中断时必须没有活动服务。恢复只替换有限的旧文件备份，遇到第三种未知哈希拒绝覆盖，最后保持实验服务停止，不自动重启有已知缺陷的旧版本。原版服务始终不属于恢复动作范围。未经核对的部分启动/退出状态可能要求根据保留日志进一步处理，不能把“已发停止命令”当作退出成功。

## 验证边界

本地已经检查 Python 3.11 语法、载荷哈希、失败请求证据门槛、安装元数据关联、有限文件交换/中断恢复、mock API 的暂存流程、cgroup v1/v2/混合布局及重测入口的版本绑定。实际 systemd、Linux 权限、目标编译和 KVM/Guest 验收仍须现场执行；这些没有用模拟测试替代。

此路径是普通 Host 文件通过 virtio-pmem/Guest DAX 复用文件页，不要求 Host FS-DAX。它没有实现完整 memfile 跨节点私有 CoW，也不代表两个 Host 的文件页已经物理共享。验证会完整读取基础镜像进行哈希校验，预热的 Host cache 必须计入后续统计。功能成功不自动代表内存净节省或性能提升；同负载对比、逐层成本和缺失数据需要另行报告。
