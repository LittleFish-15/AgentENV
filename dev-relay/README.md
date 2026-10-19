# 临时开发与人工中转工具

此目录集中存放本轮个人实验环境使用的协调入口和控制测试，方便从功能分支获取。允许含实验节点、账号、路径及已验证产物身份等环境绑定信息；不存凭据、二进制、完整日志或实验数据。

这些内容属于调试交付，最终向官方社区提交前须统一审查、移除无用辅助文件、消除个人环境绑定并整理相关提交。不要将当前实验分支原样作为上游补丁；当前也不自动改写历史。新增临时中转入口优先放在此目录。

## 当前入口：仅A的真实层格式验证

`run_a_local_layers.py` 复用已通过完整构建的b019f27 ARM64探针，以及`tools/ub-snapshot`中已验证身份的桥、broker和测试辅助函数。无需重新编译AgentENV，也不需要复制脚本或产物到B。

只在A/server1、普通jwk UID1204/GID1205执行，沿用已有源码目录：

```bash
cd /home/jwk/agent/src/agentenv-ub-0118ebb &&
git diff --quiet HEAD -- &&
git fetch --depth 1 origin feat/ub-shared-snapshot-layers &&
git checkout --detach FETCH_HEAD &&
python3 -I -B dev-relay/run_a_local_layers.py
```

上述是通用更新入口；实际实验指令优先固定本次审查过的完整提交SHA。出现本地修改/冲突时保留停止，不强制checkout或删除目录。B的排障、恢复和测试继续暂停。

脚本在独立报告目录编译小C++桥，真实探针准备raw/tar/zfile，再逐种用一个4MiB逻辑UB对象验证required-UB读取、两个本地私有upper、Base不变、导出祖先后脱离UB重开持久子快照，并自动正常释放本轮映射/对象及finalize。每种清理成功才进入下一种，不需要B或输入done，不伪造peer退出。

沿用原SDK实验的lock/pending/owner-receipt守卫。未决申请、仍有读者或删除失败均停止并保留对象身份，不绕过回执、不换名连续申请、不强制清理。UB后端物理覆盖可能取整，4MiB不是服务端物理硬配额，也不等于已测独占增量。所有可写文件仍在实验根，原服务/权限/SDK/驱动不改，不创建Guest或ublk设备。

成功标记：`A_LOCAL_UB_FORMATS_COMPLETED_NO_CROSS_NODE_CLAIM`。返回最后完整`BEGIN_RETURN_REPORT`至`END_RETURN_REPORT`，失败也返回完整汇总，不自行清pending或重复执行。真实跨节点和Guest验收仍待后续完成。仅A执行不保证现有UB控制面不依赖B；平台若也受B故障影响可能受阻，不为通过本轮恢复B或扩大权限。

报告的`source_commit=b019f27...`指复用的已编译核心产物来源；当前新增中转目录不会改变该产物身份，不需要因此重建server/daemon。

## 本地控制测试

```bash
python3 -I -B dev-relay/test_a_local_runner.py
```

测试使用真实Publisher和内存SDK double，broker/probe调用替身用于故障注入；检查顺序生命周期、探针失败清理、读者未退出、申请未知、删除失败、原guard兼容、源码身份验证。通过这些测试不代表目标SDK、真实Rust格式或Guest已验证。Windows测试使用继承ACL/短路径，Linux生产目录仍使用私有权限。
