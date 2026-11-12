# 实验三 VLAN 和 VLAN 间互通

实验三包含两个部分：第一部分用 4 台 PC、1 台 S3700 观察 VLAN 划分前后的通信；第二部分用 4 台 PC、3 台 S3700 配置 VLAN100、VLAN200 及 Vlanif 网关。

两部分分别生成独立工程，原生 PC 的 IP、掩码和网关已写入工程参数。交换机保留初始状态，由配置助手分阶段下发命令，方便记录配置前后的变化。

## 使用

需要 Python 3.10 或更高版本、eNSP；离线抓包分析需要 TShark。先在仓库根目录生成准备材料：

```powershell
python -X utf8 .\exp3\scripts\assistant.py prepare
python -X utf8 .\exp3\scripts\assistant.py check
```

已有准备工程时直接运行 `check`。生成器每次新建批次和设备 ID，保留之前的文件。工程、参考配置和 PC 参数表写入 `exp3/local/topology/批次/`；两份工程名为 `实验3-部分1.topo`、`实验3-部分2.topo`。

在 eNSP 中打开同一批次的对应工程并启动全部设备，然后双击本目录的 `启动助手.cmd`。入口会核对 eNSP 权限；若 eNSP 已以管理员身份运行，Windows 会请求以相同权限启动助手。

主菜单选 **7“完成第一个工程”** 或 **8“完成第二个工程”**。助手后台回读 PC 参数、执行有限次数的 ping、配置交换机、等待接口与 STP 就绪、采集表项，并填写本轮实测记录。若后台控件尚未就绪，按具体提示打开相应 PC 的命令行页；命令仍由脚本输入。

抓包由用户按助手提示逐条开启，每条一次，保持运行即可。助手识别该提示后的唯一新增 eNSP 捕获进程，记录链路绑定，按阶段及单次 ping 自动分段、保存和分析，不需要逐次停止或另存。原始捕获与提取窗口分别归档，旧数据不覆盖。

命令行也可查看计划，或在与 eNSP 匹配的权限下运行：

```powershell
python -X utf8 .\exp3\scripts\assistant.py run part1 --plan
python -X utf8 .\exp3\scripts\assistant.py run part1
python -X utf8 .\exp3\scripts\assistant.py run part2
```

本轮原始 PC 输出、参数、真实控件截图、各阶段交换机回读、抓包、数据表与诊断保存在 `local/runs/批次-部分/`。抓包的字段分析另存到本地 `analysis/`。截图、ARP/ICMP 或逐帧证据缺失时保持待补状态；错误或超时停止后续操作，不自动重发 ping。Word 报告在证据齐备后另填模板副本。

菜单仍保留单独的准备检查、阶段配置、只读采集、抓包分析和证据归档，供排查或补采使用。Console 使用第一部分的 2100，以及第二部分的 2200、2201、2202。运行前核对 eNSP 打开的是助手显示的批次。

## 阶段与理论预期

下表是配置推导，待在 eNSP 中采集真实结果。两部分使用各自的 PC 地址表。

| 阶段 | 配置状态 | PC1→PC2 | PC1→PC3 | PC1→PC4 |
| --- | --- | --- | --- | --- |
| `part1-default` | 第一部分，默认 VLAN1 | 通 | 通 | 通 |
| `part1-vlan2` | 第一部分，Ethernet13～22 划入 VLAN2 | 通 | 不通 | 不通 |
| `part2-access` | 第二部分，S2/S3 已配置，S1 保持默认 | 不通 | 不通 | 不通 |
| `part2-routing` | 第二部分，S1 的 trunk、Vlanif 均已配置 | 通 | 通 | 通 |

另有 `part2-l2-optional`，用于补充观察仅配置 S1 VLAN/trunk、尚未配置 Vlanif 时的通信；此时 PC1→PC3 通，PC1→PC2/PC4 不通。该阶段为辅助验证，可跳过，须在 `part2-routing` 之前执行。

单独调用配置与采集：

```powershell
python -X utf8 .\exp3\scripts\collect_switches.py --stage part2-access --apply
python -X utf8 .\exp3\scripts\collect_switches.py --stage part2-routing --apply
python -X utf8 .\exp3\scripts\collect_switches.py --stage part2-routing
```

`--apply` 下发本阶段配置并回读；省略时只查询。每次查询新建记录目录。ICMP、ARP 和截图按本地操作清单单独收集，配置回读成功与通信结果分别记录。

## 文件与验证

| 文件 | 用途 |
| --- | --- |
| `scripts/lab_spec.py` | 两部分的设备、地址、连线与理论连通矩阵 |
| `scripts/prepare_topology.py` | 生成独立工程、预填原生 PC 参数、只读校验 |
| `scripts/collect_switches.py` | Telnet 协商、分页、分阶段配置、回读与诊断日志 |
| `scripts/analyze_capture.py` | 离线提取 Ethernet、802.1Q、ARP、IPv4、ICMP 字段及请求应答 |
| `scripts/assistant.py` | 菜单入口与证据归档 |
| `scripts/run_project.py` | 两个完整工程的自动运行、实测表填写与逐帧证据对照 |
| `scripts/pc_console.py` | PC 后台控件输入、身份/参数回读、有限 ping、ARP清理与真实控件截图 |
| `scripts/capture_workflow.py` | 活动抓包绑定、阶段检查点、原始归档与 PCAP/PCAPNG 分段 |
| `scripts/launch_assistant.py` | 用户主动启动时核对并匹配 eNSP 权限 |

```powershell
python -X utf8 .\exp3\scripts\analyze_capture.py "已保存的抓包.pcapng" --scenario inter-vlan
python -X utf8 -m unittest discover -s .\exp3\scripts -p 'test_*.py' -v
python -X utf8 .\exp3\scripts\verify_preparation.py
```

`inter-vlan` 对应实验三第二部分，`port-vlan` 对应第一部分，`auto` 仅解析实际字段。测试数据标为测试夹具；协议测试与 XML 校验分别验证脚本行为和文件结构，eNSP 导入、设备通信及现场截图在实际运行时验收。

课程原件、个人操作清单、全部图片、工程、抓包和运行记录均保留在已忽略的本地目录。公开内容为通用配置数据、辅助脚本和测试。
