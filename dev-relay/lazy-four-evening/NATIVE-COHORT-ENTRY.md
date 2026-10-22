# Native四模板捕获、A快照在B恢复与回放组件

这一组件接在native provider与独立Runtime之后。A只捕获一次四个parent；B使用A导入的同一组snapshot ID，不能重新捕获B parent充当跨节点恢复。它仍需要外层协调入口完成两节点部署、私有文件传递、屏障与统一收尾；不是已经实机验收的完整方案。

## 安装和前置条件

`native_archive_cohort_install.py`默认无动作。普通实验用户执行`--install`时，只向全新的`native-archive-cohort/`安装10个固定SHA helper，不启动服务、SDK或Guest。已有或部分安装不覆盖。

每个节点应已经具备：明确的provider plan及serving代际；独立`agentenv-native-archive-v1` Runtime及匹配FC/verifier/tools；验证完整的四模板原始输入播种。B另需`native-snapshot-inputs.json`，来自A native快照完整接收与未启动仓库导入。原始native raw输入是否已完成，当前还缺现场回执，不能从旧ordinary实验推断。

控制器从明确的provider plan核node、boot、精确随机unit、PID/start ticks、ownerId、manifest身份与serving状态，并要求Runtime绑定的所有socket属于该provider。采样不再引用旧unit或旧provider路径。provider退出或变化会被标为不可用；cgroup缺失记NA，不据此丢弃Host及其他采集。

## 业务阶段

安装后的入口路径为`native-archive-cohort/native_archive_cohort.py`。不带`--run`只输出计划。

```sh
# A：新Runtime空闲时，4个native parent依次cold create / capture / delete
python3 -I -B native-archive-cohort/native_archive_cohort.py parents \
  --node node-a --provider-plan A_PRIVATE_PROVIDER_PLAN --run

# A：单节点四模板，各2沙箱；以下默认是每模板两次restore
python3 -I -B native-archive-cohort/native_archive_cohort.py replay \
  --node node-a --scenario single-a --replica-mode restore-pair \
  --provider-plan A_PRIVATE_PROVIDER_PLAN --run
```

parent成功前必须确认全局Guest空与完整cleanup。每个snapshot检查archiveVersion1、内容/层序/文件系统、catalog SHA、commit、4GiB/2CPU，并实际核验原始归档文件hash。完整捕获清单保存在新部署的`native-cohort/templates.json`，用于前一份传递组件打包。校验会读取归档文件并影响Host缓存，不能称为无扰动冷态。

B仅接受已导入A快照的回执，核相同任务、资源、replay SHA、snapshot ID、catalog及实际raw归档，再恢复。`parents --node node-b`被拒绝。双节点`--scenario dual-ab`需要协调者提供同一轮明确的`--admission-epoch`及`--completed-epoch`并操作屏障；本组件不会自行创建对端或启动SSH。请勿手工随便填写epoch绕过这一步。

`--replica-mode restore-fork`是独立能力阶段：每模板先恢复一个Guest，再通过实际Fork API创建第二个。两种模式使用不同phase目录、保留不同`replicaFormation`，不能混为同一对照。Fork与restore的副本寿命均为7200秒，Guest命令300秒、CLI330秒保持；此改动不延长任务截止时间。当前创建按模板依次执行，**没有证明并发Fork通过**。未知Fork回复保留intent、阻止后续创建，不重试未知操作。

## 记录与收尾

每阶段完整日志、逐动作退出码/起止时间、Host/PSI、实际Guest RAM VMA/整FC、Runtime/provider charge及UB journal覆盖统计留在`native-cohort/<phase>/`；sample文件、case/state、report及临时命令输出保持。不同任务并行回放，结束后做私有upper标记隔离检查，再按case ownership清理。单节点物理范围是否确实无B映射，仍由外层协调顺序及两节点回执证明。

`completeCounterfactualAccepted=false`、物理UB净节省及rootfs穷尽访问驻留为NA，直到有完整同负载对照和不重叠物理账户。SDK覆盖不是物理增量，成功完成轨迹允许保留原有非零命令，不等于所有命令成功。比较必须逐模板/slot/step检查实际退出结果向量；不能只比总数或截取成功部分。

失败时保留未知创建/Fork/删除intent。`cleanup --node ... --scenario ... --replica-mode ... --run`只恢复同boot/Runtime/config的原case journal，不重新开始任务；cleanup不要求provider仍serving，以免阻止必要Guest收尾。只有确认所有Guest释放后，才能停止Runtime，再按provider协议B释放／A核peer receipt并退役。不要用关闭终端或直接杀provider代替退役。

本地10项检查覆盖真实Fork调用数量/7200副本寿命、两restore区分、未知Fork不重试、10helper pins、capture清理不确定不发布ready、真实A归档在B选择及损坏拒绝、安装不覆盖、provider PID变化/缺cgroup。整体186交付检查通过；这些含模型API及本地文件，不是目标Linux/SDK/DAX/Guest验收。memfile真正私有CoW仍未实现。

最新集成修正：native观察器以4GiB核对实际FC RAM区间，纠正旧512MiB调用参数；仍不按大小猜测VMA。样本补充collector、精确父coordinator与Runtime host proxy的进程指标，独立失败记NA。辅助进程与Host其他账户存在重叠，SSH/kernel/driver成本未完整覆盖，不求和冒充物理净收益。
