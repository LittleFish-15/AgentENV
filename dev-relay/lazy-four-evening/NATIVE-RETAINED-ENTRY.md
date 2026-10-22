# 从native快照归档到全新UB代际

固定核心bd6d72a55066d07ceeda8db765658900ed85988b。新增`publish-retained-snapshot`与`import-retained-snapshot`，将已归档的pmem基础镜像接到原有发布/导入/lease/退役实现。它们默认只读校验；显式`--run`才新建私有准备目录并运行前台provider。没有改变NC属性、SDK适配器、KVM或Guest RAM私有化能力。

## 适用前提

需要**实际native快照**的`firecracker-manifest.json`，其中含`nativeRootfs.archiveVersion=1`，并且owner具有对应`native-pmem/00-<sha>.img`等仓库制品。现有四模板普通块设备快照没有这些字段，不能直接冒充native归档。本入口不负责把普通快照转换成DAX快照，也不宣称四模板Guest共享文件页已验收。

Runtime仍使用本夜已固定的5e6621c源码，已含归档持久化/恢复代码；本次只新增provider Python操作，不需要重编译Runtime、FC或原SDK适配器。普通rootfs缓存对照c56082c仍固定自己的2f provider，不修改其安装或参与者。以下组件使用独立目录。

## 安装与调用

`native_retained_install.py`内嵌固定核心的provider Python源和75项单元测试，不含SDK二进制、私有镜像、业务轨迹或真实对象清单。直接运行默认只打印计划；普通Linux用户加`--directory <全新绝对路径> --install`才安装并执行模型测试。成功为`NATIVE_RETAINED_PROVIDER_INSTALLED_TESTED_NO_SDK`，保留`installation.json`与`tests.log`。不覆盖已有目录，不调用SDK，不创建Guest或修改服务。

安装后的`provider_entry.py`每次先核验全部源文件SHA；`--help`列出命令。A发布者按核心README传入归档目录、native快照清单、设备运行时pins、现有SDK适配器及其SHA、已有region、明确logical/coverage预算和B的reader身份。默认校验不写文件；加`--run`后形成`binding.json`、`image-catalog.json`、`provider.json`、`preparation.json`，并在子目录`provider`启动新代际。前台不返回是正常服务状态，应保持进程；不是完成释放。

A服务进入serving后，协调者私下传递`provider/replicas.json`与其**文件SHA256**给B。B的`import-retained-snapshot`同时核对原native快照的source/layer身份、发布清单SHA、reader名单、层顺序、长度与各allocation名字，再走原map-only导入路径。B新绑定不会复制A的本地文件路径；真正恢复时，Runtime resolver从仓库hydrate并pin原始制品。

只有provider的实际ready/serving状态确认后，才把对应`binding.json`用于匹配Runtime的`AENV_DIRECT_ROOTFS_BINDING`。工具本身不启动AgentENV、不恢复或Fork Guest、不执行业务轨迹；这些步骤仍需完整native场景协调与硬件验收。不能因CLI或模型测试成功，就写成已实现Guest DAX共享或memfile CoW。

## 退役与失败

遵循原合同：先阻止新导入，停止该代际全部Guest及继承lease的子进程；B正常退役并提供准确`release.json`；A核对每个reader的ownerId/manifestSha/身份后才退役和删除自身创建对象。协调者必须保证每个reader身份只对应一个活跃importer。工具没有分布式共识或远端死亡检测。

准备回执只说明准备阶段未调用SDK；当前执行状态另看`execution.json`和`provider/owner.json`。调用provider前先落intent；异常或中断保留未知状态，不重试、不删旧对象。服务返回也必须核owner代际、finalize、owner删除ack或importer精确release回执，才能记`provider_lifecycle_released`。返回0本身不替代这些证据。

预算是对齐后的逻辑申请上限及映射后的覆盖检查，不是平台强制物理配额。发布会实际读取归档并复制进新的UB对象；不是本地memfd复制冒充跨节点RAM共享。归档磁盘/Host缓存成本也不能从净收益账户中省略。

## 已验证与未验证

75项core Python检查通过，其中9项覆盖真实归档/配置文件、无副作用默认CLI、错误身份/损坏内容/预算拒绝、生命周期调用一次、失败保留、无释放回执不成功、importer不携带owner路径。安装包另有3项本地检查，实际解包后75测试及入口`--help`通过，篡改源码会拒绝启动。Linux路径/SDK调用使用模型或未执行，不是目标UB验收。

**仍未完成：** 四业务模板普通rootfs到native制品的完整准备与部署，native Guest冷启动/capture/并发Fork/跨节点restore的现场协调验收，分布式失联回收，以及memfile真正私有CoW。此交付补的是归档重发布和导入接口，不能覆盖这些剩余项。

## 多模板共用一个代际

新增 `publish-retained-set` 和 `import-retained-set`。使用 `--snapshot-set PRIVATE_SET_JSON` 代替单快照的 `--manifest` / `--artifact-root`。选集格式为 `{"version":1,"snapshots":[...]}`；A每项为 `{"manifest":"绝对路径","artifactRoot":"绝对路径"}`，B每项只有 `manifest`，所有路径仅在各自私有文件中填写。

支持1至32个已归档native快照，最终仍受原有最多8个唯一raw对象限制。各模板按sourceImage保留层顺序和filesystem身份；相同sourceImage但不同内容或层顺序会拒绝。相同完整raw内容只发布一次，各模板绑定复用同一对象；不同raw镜像即使有相同文件，也不会自动做文件级去重。合计预算按唯一对象的4MiB对齐映射长度检查，不能把每模板分别合格当整个代际合格。

输出的 `binding.json` 为 `catalogVersion:1` 多source目录，可用于支持该目录格式的Runtime。B要求发布清单恰好覆盖选集的内容并集，拒绝缺失、额外或重复内容/对象名；用内容身份重建各模板顺序，不依赖owner全局列表顺序。一个provider/socket/SDK代际承担整组模板，沿用全部lease及peer释放语义。

新增5项集合检查包含四模板聚合、内容去重、反向发布顺序导入、source冲突、合计预算和非法发布集拒绝、默认不调用SDK。它们是本地文件/协议测试，仍未执行目标SDK或Guest。这只聚合已经存在的native归档；普通四模板快照仍需实际native准备、首次capture及完整业务控制器。

## 首次冷启动之前的已准备镜像入口

`publish-prebuilt-set --image-set PRIVATE_IMAGES_JSON` 直接接受已完成准备的raw镜像，不要求事先存在native快照。选集为 `{"version":1,"images":[{"sourceConfig":"绝对配置路径","paths":["绝对raw镜像路径"],"filesystem":"ext4"}]}`。它完整hash原始镜像、按原sourceConfig计算source身份、生成v3绑定并保留snapshotSources；不导出、不压缩、不挂载文件系统、不声称原始/转换镜像文件树已经等价。首次native Guest capture成功时，Runtime才能将这些原始镜像保存成自包含archiveVersion1制品。

B使用 `import-prebuilt-set --binding-catalog PRIVATE_OWNER_BINDING --binding-catalog-sha256 sha256:HASH`，同时提供原有publisher manifest+SHA、reader、B设备runtime和预算。导入精确内容并集，丢弃A本地snapshotSources；恢复A已归档快照时，Runtime自行hydrate仓库制品。如果B单独cold start而未提供本地源，它的capture不能称为自包含native归档。这一入口不传输VMstate或仓库制品。

所有generation命令默认校验结果现在包含 `planSha256`，可在显式启动时传 `--expected-plan-sha256`。核心重新校验完整输入、重新计算计划身份，改变raw内容、绑定或预算都会拒绝执行；然后才进入SDK。受限服务组件自动传递这个身份。

新增7项本地检查覆盖首次四模板发布、共享raw去重、B无owner路径、错误binding/replica拒绝、mutable source/预算拒绝、默认无写、raw被修改后不能执行旧计划。75项核心测试通过，不是Guest或硬件验收。完整native Runtime/冷启动/capture/归档传输/restore-Fork场景控制器仍未接合。
