# A 的停止后 ublk 字符设备清理与接续

只允许 A/server1、固定 boot、已回传的旧单Guest失败轮次，设备12/13。入口读取原post-force报告、原journal摘要，复核旧unit消失、进程不存在、块设备不存在、字符设备及sysfs对应、provider本地许可/响应0、常规FD持有者为空。任一不符停止，不把观察空等同内核引用为零。

辅助程序使用 aenv 对应版本同一 libublk-rs-sys UAPI 与 io-uring SQE128 的 GET_DEV_INFO/DEL_DEV。先检查两个设备；每次删除前再次检查。仅接受 state DEAD(0)、ublksrv_pid=-1、owner1204/1205、242:12或13及字符节点ctime早于原DELETE。节点inode/ctime在查询前后必须一致。没有STOP_DEV/强制删除/模块加载或卸载/内核修改。设备编号不被用作唯一归属凭据。

参考Linux v6.6 drivers/block/ublk_drv.c：ublk_stop_dev移除块盘、设DEAD和pid=-1；ublk_ctrl_del_dev移除设备并等待idr释放。这解释停止后仍有字符设备。参考源码不是目标openEuler逐字证明；目标必须返回符合合同的GET_DEV_INFO及DEL_DEV成功回执，之后dev/sysfs消失才算确认。
源码：https://github.com/torvalds/linux/blob/v6.6/drivers/block/ublk_drv.c

每次helper最多等待20秒，超时保留未知结果和子进程身份，不重试DELETE；最多5秒核对节点消失。DEL_DEV可能因内核引用未释放而无法完成，不能保证清理通过。禁止并行运行其他针对此unit/设备的恢复入口。两个删除都成功才解锁并进入既有post-force v2，准备并激活独立修复Runtime。原失败journal不变，normalGuestDeletePassed始终false；此清理不是正常Guest生命周期验收。

helper已本地交叉构建为AArch64 ELF，使用目标既有/lib/ld-linux-aarch64.so.1及普通glibc，未在A执行。入口内嵌固定产物，不在A重编译或安装库。所有源码/Cargo.lock与产物摘要保留；真实io_uring/内核删除仍待验证。

固定输出目录：旧部署acceptance/direct-pair-v1/dead-char-delete-v1。包含report.json、两个inspect及delete日志、helper摘要、每次删除意图/ACK/观察消失记录。目录已存在时拒绝重复。部分成功或超时不能删除此目录后重跑。

恢复边界：已停止设备删除不可逆地移除其内核登记，不能恢复旧Guest；旧Guest本已退出。UB对象/provider、旧upper/镜像/源码/journal不被删除。随后D2若启动失败保留D2日志；不自动恢复旧Runtime。需要恢复运行时，应使用匹配版本创建新的Guest，不能假称原Guest恢复。
