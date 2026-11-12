# 交换机自学习仿真实测资料（脱敏副本）

本目录由一轮已经完成的 eNSP 实验记录导出。保留三台交换机第 0～5 步共 18 份 Console 输出，以及七条链路中全部 53 帧：26 帧目标 UDP、27 帧 MSTP 背景报文。

| 文件 | 内容 |
| --- | --- |
| [实测结果](实测结果.md) | 逐步转发表及转发路径观察 |
| `console/step-0/`～`console/step-5/` | 三台交换机的脱敏 Console 输出 |
| `pcap/*.pcap` | 七条链路的脱敏抓包，可用 Wireshark 打开 |
| [frames.csv](frames.csv) | 全部帧的协议、源帧序号和相对时刻 |
| [udp-fields.csv](udp-fields.csv) | 26 帧 UDP 的地址、端口、长度及负载 |
| [mac-tables.csv](mac-tables.csv)、[tables.json](tables.json) | 逐步学习的 MAC 表 |
| [manifest.json](manifest.json) | 脱敏设备标识、MAC、IP 与发包顺序 |
| [inventory.json](inventory.json) | 数据性质、修改说明、文件 SHA-256 |

PC 和交换机 MAC 在日志、抓包、结果表与公开工程中一致替换为本地管理地址；MSTP 中的根桥、桥标识及配置名中的 MAC 同步替换。设备 ID 重新生成，本机路径和 Python 环境信息省略。文本统一为 UTF-8/LF，清理 Console 行尾空白和终端控制字符。原有 IP 均为文档用地址 `192.0.2.0/24`。

所有抓包时间共同平移，第一帧记为 0 秒，保留跨链路相对时序、帧顺序及间隔；这是相对时间编码，Wireshark 中宜选择“自捕获开始经过的秒数”。Ethernet 地址变化不影响 IPv4/UDP 校验和，原帧的 IPv4、UDP 字段与负载保留。完整帧序号与原始序号在 `frames.csv` 中对应。

前三次目标 UDP 在七条链路出现；第 4 次只沿 Client4—SW3—SW2—Client3 转发；第 5 次仅在 Client5—SW3—Client4 转发。MSTP 背景帧单独标明，不计入五次 UDP 的出现次数。

原始工程、原始抓包和全部运行记录留在本地；本目录是经过上述变换的仿真实测副本。[理论推导](../理论推导.md)和模型生成数据另行标注。

如需从自己的标准轮次导出新副本，在仓库根目录运行：

```powershell
python -X utf8 .\exp2\scripts\export_public.py "本地轮次目录" --output "新的独立导出目录" --include-stp
```

导出器对本题地址、报文格式、链路及五次发送逐项核对，遇到额外协议或地址会停止。新数据仍须人工审查后提交。
