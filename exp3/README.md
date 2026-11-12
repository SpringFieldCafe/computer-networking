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

在 eNSP 中打开同一批次的对应工程，启动设备，然后运行菜单助手；也可双击本目录的 `启动助手.cmd`：

```powershell
python -X utf8 .\exp3\scripts\assistant.py menu
```

菜单提供准备检查、阶段配置、只读采集、抓包分析和证据归档。Console 使用第一部分的 2100，以及第二部分的 2200、2201、2202。助手核对工程哈希、设备资源与 Console 所属进程；运行前仍须核对 eNSP 当前打开的批次，设备运行身份与链路状态在现场回读。

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

```powershell
python -X utf8 .\exp3\scripts\analyze_capture.py "已保存的抓包.pcapng" --scenario inter-vlan
python -X utf8 -m unittest discover -s .\exp3\scripts -p 'test_*.py' -v
python -X utf8 .\exp3\scripts\verify_preparation.py
```

`inter-vlan` 对应实验三第二部分，`port-vlan` 对应第一部分，`auto` 仅解析实际字段。测试数据标为测试夹具；协议测试与 XML 校验分别验证脚本行为和文件结构，eNSP 导入、设备通信及现场截图在实际运行时验收。

课程原件、个人操作清单、全部图片、工程、抓包和运行记录均保留在已忽略的本地目录。公开内容为通用配置数据、辅助脚本和测试。
