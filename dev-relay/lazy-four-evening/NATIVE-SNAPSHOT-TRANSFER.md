# A捕获native快照的私有打包与B仓库导入

`native_snapshot_transport.py`将A已经捕获并提交的四个native快照打成私有文件包，在B校验并导入到新Runtime尚未启动的独立仓库。它不连接机器，不创建Guest，不调用SDK，不把B重新cold-capture当作A快照恢复，也不将复制memory层文件称为跨节点Guest RAM共享。

输入必须是新的`archiveVersion:1` native快照，四模板各2CPU/4096MiB，使用明确的native tools版本。只有旧内容引用、没有原始pmem归档的快照会被拒绝；ordinary快照也不能输入此工具。

## 依赖闭合与身份

每个快照包含：catalog record、commit标记、Firecracker manifest、VM state、全部managed memory/rootfs层、按内容命名的native-pmem镜像。包还带私有selection、历史参考及A捕获清单。它们只在A/B之间私下传递，不能上传公开GitHub。

完整内容hash在打包及接收时核验。四模板共享的managed文件只打包一次；每快照原始native归档保留自己的路径，不修改源仓库，不重命名snapshot ID，不复制运行中的数据库。接收拒绝路径越界、链接、重复/额外成员、缺失文件、错误内容和不匹配capture证据。最多512个文件、合计64GiB、单文件最多8GiB；native单层最多4GiB且2MiB对齐。达到上限会停止，不自动扩大。

## 组件命令

以下命令由后续协调入口按实际准备回执填写，不要猜测路径或拿旧ordinary报告替代。默认不带`--run`只打印计划。

```sh
# A：四个parent完成capture并释放Guest后
python3 -I -B native_snapshot_transport.py pack \
  --repository A_NATIVE_REPOSITORY --selection PRIVATE_SELECTION_JSON \
  --history PRIVATE_HISTORY_JSON --captures A_NATIVE_TEMPLATES_JSON \
  --archive NEW_PRIVATE_ARCHIVE --run

# 通过已有获授权的私有传输通道将包及其SHA传到B；本工具不建立SSH。

# B：校验完整包，写入全新的接收目录
python3 -I -B native_snapshot_transport.py receive \
  --archive PRIVATE_ARCHIVE --sha256 ARCHIVE_SHA256 \
  --directory NEW_RECEIVED_DIRECTORY --run

# B：新native Runtime准备和原始输入播种完成，但unit尚未启动
python3 -I -B native_snapshot_transport.py seed \
  --directory NEW_RECEIVED_DIRECTORY --node node-b --run
```

A捕获清单须为`FOUR_NATIVE_PARENTS_CAPTURED_OWNED_GUESTS_RELEASED`，每项含snapshot ID、原始source身份、nativeRootfs archiveVersion1、catalog文件SHA及相同资源。接收后的文件再与capture清单和selection逐模板重算，不能只靠tar整体SHA推断内容身份正确。

B seed核新安装的5e Runtime、node-b、初始空cohort与unit未启动；核相同tools版本、四个本地v3绑定的source／层序／内容／filesystem。新仓库必须不存在，已有或部分仓库保持原样。先复制制品，再写commit与records；native归档设只读、文件与目录同步后写`native-snapshot-inputs.json`。它不覆盖`rootfs-inputs.json`，后者仍记录已播种的原始OCI输入。

成功回执`A_NATIVE_SNAPSHOTS_SEEDED_ON_INACTIVE_B_NOT_GUEST_ACCEPTANCE`只证明仓库准备：B此时还未恢复Guest。下一步必须由业务控制器在B恢复同一snapshot ID并验证DAX、执行、私有upper和回放结果，才能报告跨节点恢复通过。完整业务控制器仍在接合；此组件单独不能生成收益报告。

失败保留新包、接收目录或partial仓库供核查，不重试覆盖，不清理A的原始快照。原有普通rootfs对照入口不受影响。复制的VM state、memory层及native归档是持久制品；其磁盘和Host缓存开销应单列，memfile私有CoW依然未实现。

本地5项检查通过：真实四模板文件打包／接收完整回读、legacy native归档拒绝、raw内容损坏拒绝、非普通tar成员及未知路径拒绝、默认无动作／拒绝往A播种。Windows测试替代了Linux文件所有者检查；Linux互斥、目录fsync和B完整seed尚未实机执行。没有网络、SDK、KVM或Guest验收。
