# Native归档provider的受限服务入口

这是核心ba4a5c18发布/导入CLI的**服务启动组件**，不是四模板完整DAX测试控制器。需要已经存在且验证通过的native归档快照。原有ordinary四模板快照不能直接作为输入；当前四模板raw准备是否完成，未获得足够现场回执，不能假定成功或重新导出。

`native_retained_service.py`只使用已安装并测试通过的`native_retained_install.py`产物，固定其全部源码和入口SHA。A负责发布，B负责导入；只处理jwk UID1204/GID1205、既有ubsmd组984、两台既定ARM64节点。SDK适配器必须与该节点已释放v1实验保留的适配器完全相同，不重复编译。

## 准备输入

普通用户在本地私有JSON文件中填写以下字段，不上传到GitHub：

| 字段 | 含义 |
|---|---|
| `version` | 整数1 |
| `scenario` | `single-a`或`dual-ab`；B仅允许后者 |
| `installation` | 固定native provider源码安装目录 |
| `manifest` | native归档快照清单路径 |
| `deviceRuntime` | 本节点FC/verifier固定版本说明JSON |
| `output` | 全新provider准备和代际目录，不能在源安装或归档目录内 |
| `adapter` / `adapterSha256` | 已验证SDK适配器路径及带`sha256:`前缀的哈希 |
| `region` | 已有SDK region名称 |
| `logicalBudgetBytes` | 明确对齐逻辑预算，最多16GiB |
| `coverageBytes` | 明确映射覆盖检查上限，最多18GiB，不是服务强制物理配额 |
| A额外：`artifactRoot` | 仓库native归档根目录 |
| B额外：`publisherManifest` / `publisherManifestSha256` | 私下传递的A `provider/replicas.json`及其文件SHA |

双节点reader身份固定`node-b-native-retained`，单节点A没有B reader。所有路径必须位于原实验工作目录内，准备和运行输出相互分离。B准备须等A已发布并取得确切manifest；该组件不自动连接或传输私有文件。

## 启动流程

默认运行只打印计划，无SDK或服务操作。指定以下模式后，普通用户执行只读原始内容/预算校验并生成固定root块：

```bash
python3 -I -B native_retained_service.py prepare --node node-a \
  --request PRIVATE_REQUEST_JSON --directory NEW_PRIVATE_PLAN_DIRECTORY --run
```

B将node-a改成node-b，并使用B的私有请求和目录。这个prepare仍不启动unit、不调用SDK。完整校验输出保留为`validation.stdout`/`validation.stderr`；失败或超时另写失败回执，不盲目覆盖重做。

普通用户准备后，把打印的完整root块放到对应节点root终端执行并保持。root只创建本次随机身份的transient unit：`User=jwk`、`Group=jwk`、补充既有`ubsmd`组、Capabilities为空、NoNewPrivileges、Restart=no，以及有界MemoryMax/MEMLOCK。不改用户全局组、不重启ubsmd/ubse、不修改SDK权限。

准备和运行使用已有准备互斥，运行再持有该节点已有SDK互斥直到provider退出；B若尚无本实验准备互斥，只在jwk自己的relay目录独占创建该文件。这样可拒绝与普通对照或另一native代际争用，不停止已有工作。两个阶段均检查当前可用内存至少覆盖声明上限加8GiB余量；该检查不证明整个主机无背景负载。

root在启动前写入`/run/agentenv-native-retained/<unit>/intent.json`，同一计划只有一次激活尝试；已有unit或已有激活回执拒绝重复。退出码和不确定状态分别留根拥有的回执，不把systemd返回当成UB释放证明。实际provider在自己的`output`目录保留core execution/owner/replica回执。

## 退役与范围

root终端持续等待是前台provider服务状态，不能当成卡死。停止所有该代际Guest/继承lease后，用安装后的`provider_entry.py retire <output/provider>`执行原语义退役；双节点先B释放，再把B准确release.json交A，由A带`--peer-receipt`退役。**不要用停止unit、杀进程或关闭终端代替SDK退役。** 发生不确定结果时保留回执，不重发SDK操作。

这个组件不启动AgentENV、不转换ordinary模板、不生成native快照、不恢复/Fork Guest，也不运行四模板业务。现有四模板native准备器已经包含导出、压缩及DAX执行标记，早先单镜像全零UUID问题也已有finisher；需要核实际准备回执才能选择复用，不能重复64GiB复制或把三文件抽样称为全文件树等价。

本地12项参数、命令、身份、互斥、一次激活和失败语义检查通过；Linux systemd/SDK IPC实际运行未验收。memfile私有CoW和Guest共享文件页的硬件门槛未由该入口解决。普通rootfs对照仍用c56082c的一体入口，不把本组件混入其结果。

## 多快照选集与输入固定

同一个服务现在可覆盖四模板：请求中以 `snapshotSet` 代替 `manifest`，A请求不再设置顶层 `artifactRoot`；它位于选集的每个snapshot项中。B选集每项只列本地manifest。不能同时填写两种格式。其余安装、SDK、设备pins、预算、scenario及reader规则相同。

准备阶段检查每个归档与新output/plan目录分离，将选集文件、所有manifest、deviceRuntime、B publisherManifest的SHA记录在plan.inputPins中。校验结束、root激活和持有SDK互斥后的实际启动均检查这些pins；发生变化不运行。核心仍在执行时重新验证原始镜像的内容SHA，而非仅依赖这些元数据pins。

一次unit启动执行一次 `publish-retained-set` 或 `import-retained-set`，没有为四模板开四个相互争抢SDK锁的provider。集合接口仍不会启动Runtime/Guest，不能将这份服务组件当作完整四模板DAX业务测试入口。
