# Native归档Runtime隔离部署组件

本组件准备一套独立的native Runtime，使用新版server/daemon，并复用已构建的Firecracker、verifier、CLI与tools。它不是四模板回放控制器，也不会自动发布UB、创建Guest、capture、传输快照或计算收益。

## 固定组合与前置制品

| 部件 | 来源 |
|---|---|
| server、uvm-ublk-daemon | 5e6621c9c9d2e347959a61a46c7f6d99688eeb55，含native归档及读取观测修复 |
| Firecracker、aenv-native-fd-verify、CLI | 已有32ce41c0ac6436198860f888e07ef9793e58dc40协调构建回执与原始文件SHA |
| 原始四模板输入 | 原32ce准备清单；保持原输入provenance，不冒称重新构建 |
| provider安装／发布服务 | 独立的bd6d72a5版本，见NATIVE-SERVICE-ENTRY |

新Runtime构建回执必须包含五个成功阶段：archive文件、provider协议、observer源码、POSIX归档发布测试，以及server/daemon构建。已有精确成功产物直接使用；未构建时使用c56082c交付中的离线构建入口，不重编译FC/verifier/CLI。

准备一个只留在机器上的JSON选择文件，格式如下，路径和SHA换成已有制品的实际值：

```json
{
  "version": 1,
  "legacyReport": "ABSOLUTE_LEGACY_BUILD_RETURN_JSON",
  "legacyReportSha256": "64_HEX_FILE_SHA",
  "runtimeReport": "ABSOLUTE_NEW_RUNTIME_RETURN_JSON",
  "runtimeReportSha256": "64_HEX_FILE_SHA"
}
```

每份回执相邻的`artifacts/`保存其二进制。准备器分别验证回执身份、阶段、实际ELF架构、长度及SHA。不会用旧server代替失败的新构建；也不将复用的FC标为新编译。

## 准备与输入播种

默认`plan --node node-a`不写文件。显式准备命令为：

```sh
python3 -I -B prepare_native_archive_runtime.py prepare --node node-a \
  --core-report PRIVATE_COMPOSITE_SELECTION_JSON \
  --tools-report EXISTING_RUNTIME_TOOLS_RETURN_JSON \
  --rootfs-binding NEW_PROVIDER_BINDING_JSON --binding-sha256 BINDING_FILE_SHA
```

新目录为`deployments/agentenv-native-archive-v1`，unit为`jwk-aenv-native-archive-v1-node-a.service`（B对应node-b）。runtime及FC工作目录独立。要求原版服务仍在运行、相关旧服务身份不变、新目录/unit不存在；发现已有或部分安装立即保留并停止。只复制被核验的不可变依赖与指定二进制，不复制原服务数据库、日志、凭据或运行状态。生成新API凭据仅留本机。新proxy连接360秒，Guest300秒／CLI330秒任务语义不变。

四个v3绑定必须指向该安装内的verifier，且verifier/FC SHA与所选实际二进制一致；这是显式native入口，不接受ordinary-only。先按provider文档生成这些绑定。准备不调用SDK或创建Guest，也不启动unit。

准备完后，使用**已有且验证完整**的四模板接收目录播种：

```sh
python3 -I -B native_archive_inputs.py seed --node node-a \
  --directory EXISTING_VERIFIED_FOUR_INPUT_DIRECTORY --run
```

这里保留输入的32ce来源，另记Runtime版本5e；只在新unit尚未启动、初始cohort为空、缓存及partial目录均不存在时工作。校验manifest/OCI/层hash，复制到新的私有image-cache并重写node-local路径；不是重复导出或压缩raw镜像，也不是UB物理共享。磁盘复制及其Host cache开销需要计入测试。

若没有已完成的native四模板输入回执或接收目录，不能由ordinary实验成功推断其存在，更不能自动重做旧导出。当前输入完成情况尚未获得实机回执，本组件不能替代这项前置验收。

## 激活、停止与证据

完成播种且provider已按其自身合同进入serving后，运行同一准备器的`activation-plan --node node-a`，在对应root终端执行打印的完整固定块。root复核文件SHA、输入与绑定、同boot和旧服务身份，只启动精确的新unit；不启用自动重启、不修改SDK守护服务或用户组。Runtime仍需要已有KVM/aenv组和原方案所需namespace能力。

使用准备回执给出的health命令检查新服务。**健康检查不表示Guest DAX、执行或快照能力通过。** 原始输入、native Guest创建、archiveVersion1 capture和跨节点restore/Fork仍需业务控制器接合与实机验收。

停止时先由业务生命周期确认全部Guest释放、无未知请求，再运行`rollback-plan --node node-a`。它只生成针对当前新Runtime/PID/startTicks和host proxy的停止块，root再核API空闲及cohort状态，停止该新unit并通过已取得pidfd结束其host proxy。保留新安装、日志、快照、所有provider对象及旧服务；UB退役必须另按provider准确release/peer receipt合同完成，不能把停止Runtime当UB释放证明。

本地七项检查覆盖组合选择、坏文件/不完整构建拒绝、实际inventory读取新server、默认不动作、新unit/rollback边界、proxy截止修复。Linux权限、systemd启动、完整播种与Guest业务尚未实机执行。组件不可报告为完整跨节点CoW部署成功。

当前native启动环境显式移除外部继承的direct-memory、UB-memory、UB-rootfs和旧direct-rootfs变量，只设置本次声明的native rootfs绑定，避免把其他场景的内存/缓存路径混入。
