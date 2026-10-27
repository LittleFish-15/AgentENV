# 从现有A记录续做，全程API优先在线代码

用户已确认root curl + Accept application/vnd.github.raw+json可下载固定版本。在线v2优先此API路径，必要时回退raw；仍校验完整commit、长度和SHA。底层测数管线保持12549737/87aa3fae，状态、runID、负载和超时不变。

当前已出现ready-a Existing Guest attempt，不可再执行A启动。A_export_current_online_handoff_v1.py --release <本发布完整commit> --export只在A/root核已有记录和当前状态：
- 只有成功ready-envelope、无未决退出、同一Runtime/provider/FC和实际绑定仍在，才导出ready-b。
- 若A已有完整正常退出回执和静止状态，导出finish-b。
- 存在部分退出、未知请求、Guest不在、状态不匹配或已出现测数目录时，不启动任何Guest，不改journal，返回当前状态。

导出的短在线命令保存在/home/jwk/agent/next-online-<phase>-9c8f00d962c848c4b07e089bd69c5476.sh，jwk可读，并打印BEGIN_NEXT_B_ONLINE_COMMAND。只读校验和代码缓存/交接文件写入，不调用创建、删除或服务修改接口。私有回执不上传GitHub。root应直接从终端或保存文件中转，避免经过富文本修改Python引号和URL。

成功后在B/root执行新导出的命令；后续NEXT步骤都由在线v2生成。不要重跑已经完成的A阶段。底层固化版本及所有验收/测数门控保持，导出成功不是新实验通过或已有收益结果。
