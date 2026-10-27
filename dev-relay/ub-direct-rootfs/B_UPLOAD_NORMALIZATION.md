# 修复B上传产物元数据后续做原恢复入口

原入口的uid1204已正确，但组合检查还包含普通文件、单硬链接、group/other不可写；错误文本未打印完整元数据，不能仅从uid推断具体失败条件。该拒绝发生在artifact SHA检查及任何服务动作之前，没有建立B recovery目录或发信号。

新B_normalize_upload_and_recover_OFFLINE_root.sh仅B/root。先打印实际type/uid/gid/links/mode/bytes，读取固定目标上传文件的字节并严格核24758576B及5291c267...SHA。允许普通上传文件，或仅指向/home/jwk/agent范围内普通文件的叶符号链接；特殊文件、外部链接、错误内容一律停止。

校验通过后创建独立临时文件，写相同字节、fchown1204:1205、mode0600、fsync，再只原子替换/home/jwk/agent/uvm-ublk-daemon-private-delete-v1这一上传路径。不会chmod其他硬链接指向的同一inode，也不会修改符号链接的源文件；二进制内容不变，无编译。完成后再完整执行原固定B恢复入口0f39df20...，其停止/设备身份/许可/部署门控保持不变。

若内容或路径校验失败，不改上传文件、不运行恢复；权限规范化成功但后续恢复失败时，保留后续progress，不自动重试。目标Linux权限操作仍待回执；本地仅完成源码审查、Python3.11 AST及内嵌原恢复入口逐字校验。无内核/模块或UB协议改变。
