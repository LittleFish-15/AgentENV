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
