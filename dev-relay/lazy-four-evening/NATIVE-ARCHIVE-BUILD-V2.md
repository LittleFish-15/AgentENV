# pmem仓库持久化修复构建包 v2

固定核心源码67654884d0d71481fd25b46ab115d78ce258e614。本版补齐POSIX归档发布顺序：验证后的独立基础文件设为只读并sync，归档目录和快照目录sync后，清单经临时文件写入/sync/原子rename/父目录sync，再允许仓库catalog提交。新增两个Linux仓库文件测试，覆盖源文件后续修改不影响归档、只读权限、清单不保留本地路径、归档校验失败不发布清单。

本地ARM64 `cargo check --tests`通过，证明相关代码与新增测试可编译；没有在本机执行Linux目录fsync，也不是断电验收。第一次检查发现新增测试缺少PermissionsExt导入，已修复并重验通过。现有共享FD、KVM、Guest DAX平台门槛没有改变。

`A_build_native_archive_v2.py`默认只打印计划；显式`--run`才会在A普通jwk下工作。复用已有A导出工具的固定工具链/依赖缓存，在新的`builds/native-archive-release-v2`解包固定源，依次执行原始归档文件测试、provider协议测试、`agentenv --lib native_archive_`仓库测试、server release构建。任一步失败停止，保留完整日志及return.json；已有目录不自动覆盖或重做。SIGTERM转为有界编译子进程收尾，不将取消写作成功。

该包只产生server候选与校验回执，不启动SDK、不分配UB、不创建Guest、不替换或启动服务、不改镜像。真实pmem仓库生命周期还需协调原始镜像发布、节点绑定、Guest恢复与退役，不能单靠构建成功验收。memfile跨节点私有CoW与自动SDK重发布仍未实现。

普通rootfs单/双节点入口仍固定使用6ab53dd Runtime/daemon与2f1550f provider，属于另一条已冻结的对照版本。普通块路径没有启用native archive capture，因此无需为此持久化修复重新构建其二进制。不得把这个v2候选当作已被普通rootfs入口部署，也不要手工覆盖那条入口的固定二进制。

源码包1050个成员，SHA256为ceb44277c1b0d8e5bf3b5ca3b8192682435378b851a84be955d18667e8a8e3c7。仅作为native生命周期待验收阶段的候选构建；今晚未执行目标机工作。
