# 临时开发与人工中转工具

此目录集中存放本轮个人实验环境使用的协调入口和控制测试，方便从功能分支获取。允许含实验节点、账号、路径及已验证产物身份等环境绑定信息；不存凭据、二进制、完整日志或实验数据。

## 当前优先：B恢复后启动两套服务

用户已明确B恢复并要求先启动原版/修改版检查健康，不再单独做环境调查。仅普通jwk执行以下prepare/install/health，root只在最后直接粘贴打印的审查块。B不用编译或下载依赖，A已有服务与安装文件不改。

1. B取得本功能分支审查过的提交，在已有源码目录运行`python3 -I -B dev-relay/deploy_b_ub.py prepare`。缺源码目录时用Git新建，不删/覆盖旧目录。该命令核对原版v4安装和原二进制；若确实重启过且原单元不在运行，只原子刷新原启动回执的boot_id/host_netns/host_mntns并保留旧回执，不改原配置/数据/程序。创建带身份标记的`/home/jwk/agent/relay/ub-b019f27-artifacts`接收目录；原单元已正常运行则保留。
2. 用既有文件转运把A的qkkuxbta artifacts中`server`、`aenv`、`uvm-ublk-daemon`三个文件传到该B目录，无ZIP、不传凭据。可在A以jwk用正常SSH/SCP直传B原地址141.61.84.87，保持主机密钥验证；若直达不可用，用已有绿区SFTP中转相同三个文件，不改网络/SSH配置。
3. B运行`python3 -I -B dev-relay/deploy_b_ub.py install`。复用B原版native/deps，校验三个修改版产物并安装到独立前缀，准备r/ub-b-b019、18081、独立key和aenv-ub。若原版尚未启动，报告original_health=null而不是伪报204；本步骤仍不启动服务。安装器会打印经固定SHA核对的`BEGIN_REVIEWED_ROOT_COMMANDS_COPY_BODY_ONLY`块。
4. 审阅该精确B范围后，把标记之间的块体直接粘贴到B/root Bash终端，不用root执行仓库/jwk可写脚本。保留已运行原版，否则创建原已批准的jwk-aenv-ae9c626-node-b.service；只新增jwk-aenv-ub-b019f27-node-b.service。应用均User/Group=jwk、仅进程kvm/aenv、CAP_SYS_ADMIN/CAP_NET_ADMIN和PrivateNetwork/PrivateMounts；两capabilities高权限不局限/home，不变更持久组/设备权限/宿主网络。A的单元批准不是B的隐式授权，打印的B具体内容须经用户审阅执行确认；没有脚本自动root/systemd-run行为。
5. B运行`python3 -I -B dev-relay/deploy_b_ub.py health`，一次检查原版和修改版身份、namespace自证、HTTP204、修改版CLI与各自cap0宿主代理；成功B_UB_AND_ORIGINAL_SERVICES_HEALTHY。再开新的B/jwk SSH会话运行相同入口`health --post-disconnect`，确认两代理存活，不自动重启掩盖断线失败。可source `/home/jwk/agent/env-aenv-ub-b019.sh`使用aenv-ub；旧aenv保持原版。

任一步失败即返回完整汇总/错误，不清目录、不强制checkout、不重复申请权限、不停止现有服务。未知已有单元/文件或活动旧单元的过期回执均保留，不盲目修复。模板/Guest/SDK实验不在本服务启动批中；服务正常后，按原版双沙箱CoW→修改版UB关闭对照→实际快照预算/发布→修改版UB开启→跨节点CoW依次验证，避免将UB一份源对象误称所有节点物理Guest RAM仅一份。

入口以B adapter配置公共部署逻辑，安装时复制受哈希约束的wrapper+library到B自身libexec。A已安装的fdadce3启动器和运行态不覆盖；已有A config文本逐字节回归检查。B控制测试`python3 -I -B dev-relay/test_deploy_b_ub.py`，结合原A部署控制测试及root块bash -n检查，不当作B目标已启动证据。

这些内容属于调试交付，最终向官方社区提交前须统一审查、移除无用辅助文件、消除个人环境绑定并整理相关提交。不要将当前实验分支原样作为上游补丁；当前也不自动改写历史。新增临时中转入口优先放在此目录。

## 一次性原版父样本准备

v3不再传diskSizeMB=2048：标准OCI转换基底在该固定版本为64GiB虚拟盘，2GiB请求会触发
禁止缩小检查。省略此字段沿用基础镜像大小，不扩盘/缩盘；512MiB RAM保持不变。
虚拟盘容量不是内存或独占物理磁盘占用。成功捕获后增加memory/rootfs持久层元数据、
可见层文件大小和st_blocks分配量（不将其当共享RAM或精确磁盘独占）。

针对已回传的v2特定400容量拒绝，v3会核对pending与完成报告一致、输入相同，按唯一
cow_parent_run元数据查询全部状态；只有无匹配沙箱且旧OCI全摘要再次通过才备份旧pending，
复用旧OCI目录、不联网重下镜像，进行一次新请求。其他错误/不明确/已有对象一律保留停止。
没有删除旧报告/工作目录、强制清理或循环重试，旧创建证据与新尝试关联在报告中。

v2修正目标机首次网络失败：子进程只继承用户当前已有的HTTP(S)/ALL_PROXY、NO_PROXY与
标准CA路径变量；ALL_PROXY仅在缺少协议专用代理时映射到Go支持的HTTP(S)_PROXY，
保留现有绕过列表并加本机loopback。没有新代理或DNS服务器，没有system resolver变更。
报告只列变量名称，不输出代理值。无可用已有网络路径时仍停止，不绕过TLS或修改权限。
用户私有REGCTL_CONFIG设置官方v0.11.5的incDockerCert=false/incDockerCred=false，
避免导入root所有的Docker专用目录，正常系统CA/TLS验证仍启用。
stdout/stderr分离，成功manifest正文原样哈希；诊断stderr脱敏并限制大小，失败时
自动把尾部错误及退出码放入BEGIN/END报告，避免再单独中转cat日志。

`cow_parent_once.py --image REGISTRY/REPOSITORY@sha256:DIGEST --workdir /guest/path --warm-module MODULE`
仅A/server1普通jwk。复用原版ae9c626的regctl/aenv/依赖和18080端点；通过宿主用户环境
下载一个已固定摘要的ARM64 OCI镜像，再由隔离Runtime读取本地ocidir引用。元数据声明的
压缩输入须<=512MiB，磁盘可用>=8GiB；这是前置检查，不是文件系统硬配额。
读取整个输入做哈希发生在测量前的准备阶段，不能把它称为冷缓存/按需读取实验。

最多一次冷启动请求：1vCPU/512MiB RAM/rootfs继承基底大小，900秒TTL、autoPause=false，
禁止Guest公网访问。只在Guest执行指定工作目录的Python模块导入，捕获独立随机别名父快照，
通过run ID核对持有身份后删除本批父沙箱并GET确认404。父快照与校验后OCI输入保留供后续
同父孩子实验。没有UB申请、服务/权限/主机网络变更或benchmark回放；成功标记为
`ORIGINAL_PARENT_SNAPSHOT_READY_PARENT_RELEASED`，不是CoW验收。

在冷启动请求前持久记录pending；请求不明确、清理不明确或已有pending均停止，不重复创建，
不手工删回执。HTTP错误包含经过脱敏的标准错误信息。CLI临时凭据仅存在私有运行目录，
finally删除，不写入源码/公开报告。所有日志和状态均在/home/jwk/agent内。
本地`test_cow_parent_once.py`验证正常捕获/清理、导入失败清理、创建不明确不重试、
持有身份不符不删除；真实ocidir接入、Guest启动和快照仍须目标验证。

这是通用AgentENV辅助脚本；私有benchmark源码与轨迹不复制到此公共目录。

## B重启后的精确恢复

`recover_b_after_boot.py` 是普通jwk运行的独立入口。仅B、两实验单元均not-found/PID0、
18080/18081未监听、代理锁未占用时继续。核对六个已安装二进制摘要、两套安装身份、
修改版启动器/库摘要；只有回执boot_id与当前boot不同，才把指定旧运行回执和拒绝连接的
旧socket逐个移入本轮报告备份，更新installation.json的boot_id/host_netns/host_mntns。
业务state、配置、二进制、其他文件、全局服务/权限均不修改；没有递归删除或进程信号。
同boot仍有运行状态、活动单元/监听者、身份不同、并发变化都停止保留。

成功`B_REBOOT_CONTEXT_PREPARED_NOT_STARTED`后打印完整Python stdin root块，避免Shell
美元符号转录损坏。用户审阅后直接粘贴至B/root；root只执行所显示的标准库管理代码，
应用仍由精确临时单元User=jwk启动。两项capabilities、进程kvm/aenv组和私有namespace
沿用已展示范围，不设开机自启、不修改Restart、不root执行jwk可写脚本。
之后普通jwk运行既有B health启动cap0代理，再断开重连运行已有cow_p0.py node-b。
成功准备/提交均不是服务健康通过。失败备份目录保留，不自动恢复旧boot回执或全局清理。

本地检查：`python -I -B dev-relay/test_recover_b_after_boot.py`；包括同boot保护、
文件变更保护、全部单元先检查、仅三字段更新、指定运行文件归档及root块语法/范围。
Windows测试目录使用继承ACL，Linux生产仍0700。目标恢复尚需回执。

## P0 服务收尾、样本与计量能力

`cow_p0.py node-a` / `cow_p0.py node-b` 是独立标准库脚本，可单文件转运，
不依赖当前源码checkout版本。应在关闭旧SSH并重新登录后，以普通jwk执行。
它校验部署回执和启动器摘要，调用已安装启动器的`health --post-disconnect`，
不补启动代理。然后用固定loopback端点只读查询模板/快照，限量枚举本实验
state中的catalog record和image.json，分别列memory/rootfs层元数据及可见文件大小。
不读取层数据、不输出配置原文/凭据/环境变量，不把声明摘要当成内容校验通过。

P0保存服务进程smaps可读性和整进程汇总（不是Guest RAM），只在自身报告目录
创建四页小文件测试mincore并清理，读取自己的pagemap判断PFN屏蔽；这些结果
不代表未来Guest或块设备采样权限。cachestat暂未调用，不猜syscall编号。
I/O配置只取数值/枚举白名单，不把配置声明当实际fd flags验证。

成功采集标记`P0_COLLECTED_REVIEW_CAPABILITIES_AND_SAMPLE_INPUTS`，不是CoW通过；
缺少权限/样本、分页/枚举上限会明确记录，不能将未知写成0。每节点返回完整
BEGIN_RETURN_REPORT/END_RETURN_REPORT；完整文件在该次report_directory。
无SDK、Guest创建、镜像下载、服务管理、权限变更或全局缓存清理。
下一步根据两节点真实输入固定P1样本并绑定Guest映射采样，不自动选未知镜像启动。

本地检查：`python -I -B dev-relay/test_cow_p0.py`。本地替身检查不代表
目标Linux内核的mincore/PFN可用或正式Guest实验已执行。

## 历史入口：仅A的真实层格式验证

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

## B健康失败时的一次汇总

`deploy_b_ub.py health` 先验证原版，再验证修改版。若任一步失败，
`b-both-services-v2` 报告会标明 `failed_phase`，并分别收集两套服务的
systemd状态/退出码、当前启动周期内最多40条单元日志、各自5个应用日志的
末尾最多6000字节及修改时间、安装回执的启动周期与运行目录文件元数据。
缺失、无权限或读取失败均单独报告，不再用空 `logs` 隐藏原版错误。

失败诊断不启动/停止/重启服务，不清理socket/回执，也不调用SDK。
原版失败时，修改版只做只读诊断，不能据此称完整健康检查通过；单独的
HTTP204也不能替代进程身份验证。应用日志可能属于旧启动周期，需结合时间判断。
健康检查正常路径仍可按既有授权启动普通宿主代理。

已有安装只更新源码目录后运行 `health`，不重跑 `prepare` 或 `install`，
不替换部署目录内的固定启动器/二进制。检查脚本版本与 b019f27 核心产物版本分别记录。

## 本地控制测试

```bash
python3 -I -B dev-relay/test_a_local_runner.py
```

测试使用真实Publisher和内存SDK double，broker/probe调用替身用于故障注入；检查顺序生命周期、探针失败清理、读者未退出、申请未知、删除失败、原guard兼容、源码身份验证。通过这些测试不代表目标SDK、真实Rust格式或Guest已验证。Windows测试使用继承ACL/短路径，Linux生产目录仍使用私有权限。

## A 原版受控写入、缓存计量与后代恢复

`cow_controlled_once.py` 复用 `cow_marker_prepare_e5b9050.py` 已建立并实际验证的测量快照。
与 `cow_ram_readonly.py` v5 配套，依赖均固定 SHA256；不重复建父样本、不下载镜像、不编译运行时。
这是带 16 MiB RAM 标记和 4 MiB rootfs 标记的 PyPika 派生模板，不是原先无标记基线，也不是完整 agent_replay。

普通 A/jwk 启动后最多同时恢复两个 512 MiB Guest。打印完整、可审查的 root 只读 Python 块，须在 240 秒内
直接粘贴到 A 已有 root 终端；不要 root 执行任何 jwk 可写脚本文件。块只读取固定 PID/start_ticks、固定快照
及其 lower/upper/cache/Guest 页元数据，通过一次性 0600 Unix socket 返回采样结果。socket 双方检查 SO_PEERCRED，
root 额外绑定普通控制器 PID/start_ticks、socket dev/inode；固定四阶段，不接受任意代码、路径或新 PID。
普通控制器负责 Guest 写操作和报告落盘；root 不执行 Guest 命令、不读 Guest 内存内容、不修改系统配置。

四阶段为 baseline、a_first（沙箱 A 第一段 RAM 与自身文件各写 4 MiB）、a_repeat（相同内容重复写）、
b_disjoint（沙箱 B 第二段 RAM 4 MiB 与自身文件写入不同内容）。每阶段两侧校验全部标记内容，三次 root 采样；
Guest GPA 数组采样前后必须相同，Host pagemap 在读取 flags 前后检查稳定性。GPA 经实际 Firecracker 内存区域 API
转换到 Host VMA，仅统计指定 4096 个标记页，排除 zero/KSM/compound/未知页后才比较预期。
初始四段应各有 4 MiB 共享页；A 首写后为 [0,4,4,4] MiB，B 写另一段后为 [0,0,4,4] MiB。
重复写比较所观测 PFN/GPA 身份；这不是每次分配事件跟踪，不能据此宣称系统从未发生任何瞬时分配。

同时保留同事口径整进程 VmRSS、smaps_rollup PSS、每轮 Σ(RSS−PSS)/(n−1) 的 min/max；与 Guest RAM PFN 统计分列。
rootfs lower 按 dev/inode 去重，upper 分实例计 data/index 文件长度、分配量及驻留页；memory lower、memory ublk
和 rootfs ublk page cache 单列，不能直接相加为 Host 总内存。mincore 不读文件内容或触发预热；Guest 标记校验
自身会读取标记，场景明确为预热受控实验，不称冷缓存。完整原始采样写入每阶段 `*-root.json`，返回汇总包含三次
缓存/文件统计和整进程 min/max，缺项保留 null/错误。相同 inode/page cache 不证明两个消费者访问集合完全重合。

root 返回完成消息后，普通控制器最多捕获一次 A 写后快照，删除 A、验证 B 不受影响后删除 B；顺序各恢复一个写后
后代和原测量模板，验证写入继承和 Base 标记未改。合计最多 4 次恢复、1 次捕获，同时最多 2 Guest。
保留原快照、测量快照和写后快照用于审查；仅按本 run metadata 删除已知自己创建的 Guest，并逐个 GET 404。
恢复/捕获结果不明、采样失败或超时不重试，保留 pending/日志。不能手工删除 pending 再跑。

成功结束标记 `CONTROLLED_OBSERVATIONS_AND_GENERATION_CHECKS_COMPLETED_REVIEW_MEASUREMENTS` 只表示流程完成；
物理预期是否符合、重复写观察、缓存可测性与最终验收分别报告。UB、修改版、B 和跨节点均未由本脚本验证。
本地检查：`test_cow_controlled.py`、`test_cow_ram_measurement.py`、`test_cow_marker.py`；模拟检查不代替目标运行。

## A修改版 UB 关闭的同模板对照

cow_modified_once.py 复用已通过原版受控验证的同一测量模板，不冷创建新父样本、不重编译、不下载镜像。
默认 prepare 仅检查/生成报告；显式 prepare --apply-reviewed 表示操作者审查并接受以下有限范围：

- 仅A修改版 /home/jwk/agent/deployments/agentenv-ub-b019f27，确认两Runtime库存为空、主进程稳定。
- 复制选定模板的2个memory层、14个rootfs层、vm_state.bin、firecracker-manifest.json；独立目标inode，
  内容摘要检查，最多2GiB输入，不硬链接原版文件，不覆盖任何冲突文件，不导入其它模板/别名/凭据。
  数据完成后写commit，再最后写原样catalog record；直接snapshot UUID解析无需别名。
- 仅增加Firecracker work_dir=/home/jwk/agent/r/fc-a-ub、serial_dir=修改版logs/firecracker、log_level=Info。
  同步修改该部署启动器config_text中的相同三个值及installation.json的launcher_sha256，保留严格匹配校验。
  原配置必须精确符合已部署版本，不接受未知自定义。配置、启动器、安装回执全部备份到本次报告目录。
- 准备自身不重启服务。它打印完整root块；操作者直接粘贴到A已有root终端，只重启
  jwk-aenv-ub-b019f27-node-a.service一次。root先验证配置/启动器/回执摘要、两主进程身份与修改版空库存，
  重启后检查原版PID未变；不得root运行jwk可写脚本文件。再次粘贴会因旧PID不匹配停止。
- 原版文件、原版服务、B、设备权限、系统网络及开机启动策略均不改。

重启块返回成功后，以普通jwk执行同一脚本 run。它检查新PID/健康/准备回执，使用共享受控实验引擎，
明确指定18081与修改版短目录/单元/报告pending。四阶段、三样本、两实例写隔离、后代/Base检查与清理预算
和原版一致（最多4恢复、1捕获、同时2个512MiB Guest）。root采样块只读，无需done；原版进程前后核对。
UB索引没有注入；已核对固定启动器构造的新环境，不继承宿主随意环境。此批不是UB开启或跨节点验证。

复制和摘要检查发生在正式采样之前，会预热相关文件缓存，不清除缓存。必须把该准备差异写进对照报告；
不可将修改版导入后可能更大的lower page cache解释为UB开销，也不可假称与旧原版初始缓存状态严格一致。
此批先验证同模板的功能/页分离/upper变化，完整同条件缓存和净收益验收保持待验证。

失败保留prepare/pending/原始日志，不盲目重跑、删目录或恢复旧部署。安装器旧源码中的config_text不再匹配
新配置，后续健康入口使用已同步的部署启动器；不重新安装覆盖本次配置。新增本地测试test_cow_modified.py
覆盖配置/启动器一致性、完整依赖选择、摘要/冲突/跨部署硬链接拒绝及修改版路由，Linux目标行为仍待回传。

## A修改版内部代理旧socket恢复

已收到A实际失败日志：内部代理报 New API socket already exists; preserved，启动器随后退出，
原版主进程保持运行，修改版临时unit已not-found。不是Guest/UB错误，不能把不存在单元的Result=success当成功启动。

deploy_a_ub.py现在在内部代理自己的排他flock下检查api.sock：仅jwk自有socket、路径未重定向、连接明确
ECONNREFUSED、前后dev/inode/mode/uid/mtime一致才原子改名为同运行目录的api-stale-随机值.sock。
不删除旧文件；活监听者、未知错误、锁占用、普通文件/符号链接/身份变化都保留并停止。新启动仍以jwk执行，
该检查在capability已清除的内部代理子进程内完成；不改变systemd权限或namespace。

recover_a_modified_proxy.py是针对本次已确认失败的交付入口。默认仅核对/备份候选；
--apply-reviewed才在修改版unit缺失、原版PID不变、三个准备摘要正确、boot及namespace一致、二进制校验通过、
尚无实验pending时归档拒绝连接的旧socket，并只给已安装修改版启动器加入相同guard。
同时更新installation launcher摘要和比较准备回执的两个摘要，保留原始备份，不重拷模板、不动配置/二进制。
它打印固定root块，由操作者直接粘贴，按原批准User=jwk/能力/私有namespace参数重建同名临时单元；
不是root运行jwk可写脚本，也不启停原版或B。已有任何unit则停止，不以restart覆盖它。

修复准备成功A_MODIFIED_PROXY_REPAIRED_UNIT_NOT_STARTED后执行打印块，再直接运行原有
cow_modified_d2285fe.py run，继续四阶段实验和只读root采样。不要重跑模板prepare或旧restart块。
修复准备/提交单元均不等于目标健康；最终以run的实际检查和测量回执为准。test_modified_proxy_recovery.py
验证拒绝连接/活监听/错误/身份竞态/排他锁/精确旧源码变换以及root参数边界，Linux服务恢复仍需回传。

### 运行自证记录的重启刷新

A随后实际越过proxy检查，却在runtime-attestation.json处失败：inside原来调用安装用dump/put，
新PID/start_ticks与旧内容不同就停止。现在仅该调用改为publish_runtime_attestation，put/dump对安装文件
仍保持不可覆盖。新函数要求当前UID和unit MainPID绑定，旧记录revision/UID/intended_executable合法；
旧PID消失或已被不同start_ticks复用时备份旧记录，再检查文件身份/内容与unit PID未变，原子刷新这个固定文件。
旧进程仍活、未知记录、重定向或并发变化都保留停止，不杀进程、不扩大覆盖路径。

recover_a_modified_runtime.py依赖上一轮已校验的recover_modified_proxy_ceb26a9.py及现有比较工具，
只应用这一精确调用/函数修复，继续使用原socket检查/归档、备份与固定unit恢复块；有独立恢复回执，
不重跑模板准备、不删除旧恢复记录。成功A_MODIFIED_RUNTIME_REPAIRED_UNIT_NOT_STARTED后执行打印root块，
随后已部署health && cow_modified_d2285fe.py run。health失败时shell的&&不会进入Guest实验。

test_runtime_attestation_recovery.py使用真实临时JSON文件，替代Linux进程/设备/namespace/代理子进程调用，
执行完整inside路径两次并检查两次到达server exec入口；另覆盖活旧PID、PID复用、未知记录、当前记录幂等、
unit改变及全局安装dump不放宽。此为本地模拟启动路径验证，不是目标Linux服务健康证明。
审查其余写点：proxy api.sock已有受限归档；host-proxy.json已有历史备份/临时替换路径，活代理保持复用；
server/proxy日志追加；ublk客户端已有socket占用检查/旧socket处理。本次不改这些已有路径。

## A修改版独立共存部署

A已回传上述raw/tar/zfile实际运行全部成功，SDK正常清理。下一阶段使用`deploy_a_ub.py`；B仍暂停，最终跨节点/Guest验收仍未完成。

只在A/server1、普通jwk执行安装准备：

```bash
cd /home/jwk/agent/src/agentenv-ub-0118ebb &&
python3 -I -B dev-relay/deploy_a_ub.py install
```

它校验qkkuxbta三个修改版二进制SHA，读取原版安装回执和原服务健康，独立复制原版只读native/deps输入（不复制状态、日志、缓存、API key/凭据），不重新下载或构建。新配置、认证、业务状态和运行目录分离，保留原服务/文件。目标定义如下：

| 项目 | 原版保持 | 修改版 |
|---|---|---|
| 安装 | deployments/agentenv-ae9c626-baseline | deployments/agentenv-ub-b019f27 |
| 宿主API | 127.0.0.1:18080 | 127.0.0.1:18081 |
| 临时单元 | jwk-aenv-ae9c626-node-a.service | jwk-aenv-ub-b019f27-node-a.service |
| runtime | r/node-a | r/ub-a-b019 |
| daemon socket | 原路径 | r/ub-a-b019/ublk.sock |
| CLI | 现有aenv | 新目录cli/bin/aenv-ub |

所有相对路径均在/home/jwk/agent下。未知已有目录、文件、端口或单元均停止保留，不覆盖、不清理、不全局kill。安装仅启动ldd/CLI版本等只读检查子进程，不启动服务、代理、Guest、UB SDK或设备测试；缺依赖一次报告，不安装系统包/改权限/加载模块。私有key不写Git或回执输出。

成功`A_UB_INSTALLED_AWAITING_NEW_UNIT_APPROVAL`，返回完整BEGIN/END汇总。文件准备不等于部署完成。`start_a_ub_REVIEW_ONLY.txt`中是拟定的精确管理员启动范围，尚未获批准：仅新增上述修改版单元，User/Group=jwk，进程补充kvm/aenv组、两项CAP_SYS_ADMIN/CAP_NET_ADMIN，PrivateNetwork/PrivateMounts和后续普通用户loopback代理。两项capability不受/home路径约束；不改持久组/设备权限或原服务，不在root UID执行jwk可写脚本。完成普通安装后先审查确认，再由用户在root终端直接粘贴已审查内容；安装脚本不会执行或要求绕过批准。

获批并提交新单元后，以jwk运行：

```bash
python3 -I -B dev-relay/deploy_a_ub.py health
```

该步骤校验新服务进程/能力/namespace自证及实际systemd属性，必要时启动仅本实验的普通宿主代理，真实HTTP204三次、CLI只读list和原18080健康/原进程不变。特权进程/proc链接不可读时保留PTRACE_ACCESS_DENIED，不提权绕过；结合启动前自证、相同PID/start_ticks和单元属性，不伪报直接读取成功。失败自动附仅新实例的有限日志并过滤key，不重启任何服务。

健康成功后换一个新的jwk SSH会话，以相同目录运行：

```bash
python3 -I -B dev-relay/deploy_a_ub.py health --post-disconnect
```

本模式不重启代理掩盖断线存活失败。最终`A_UB_AND_ORIGINAL_SERVICES_HEALTHY`后才可记A共存启动通过，仍非Guest/UB路径通过。不要注入已清理的A-local replica索引；真实Guest快照、模板与新预算就绪后另行发布活对象。CLI可用`source /home/jwk/agent/env-aenv-ub-b019.sh`加载，仅增加独立aenv-ub入口，不改.bashrc或原aenv。

本地安装/隔离检查：`python3 -I -B dev-relay/test_deploy_a_ub.py`。fixture替代Linux身份、设备、systemd及内核namespace，验证真实文件复制/哈希/原版不变/配置凭据隔离/冲突保留，并实际测试本机TCP字节中转；不是目标安装或权限启动证据。临时单元不持久化，重启后须按已确认配置重新激活；不为本阶段测试主动重启主机。
