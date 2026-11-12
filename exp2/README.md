# 实验二 交换机自学习

按交换机自学习实验的五次发包顺序整理理论推导，提供配置命令、eNSP 工程、实验助手，以及脱敏后的仿真实测日志和抓包数据。

| 内容 | 文件 |
| --- | --- |
| 理论分析 | [理论推导](理论推导.md) |
| 各交换机配置 | `config/SW1.txt`、`SW2.txt`、`SW3.txt` |
| 通用拓扑生成 | `scripts/prepare_topology.py` |
| 推导和模型 PCAP | `scripts/switch_model.py` |
| 逐步实测表采集 | `scripts/collect_switches.py` |
| 抓包字段提取 | `scripts/analyze_capture.py` |
| 原生 PC 工程与实验助手 | [pc-assistant](pc-assistant/README.md) |
| 18 份实测日志、七条链路抓包及结果表 | [evidence](evidence/README.md) |
| 公开副本导出 | `scripts/export_public.py` |

公开工程和实测副本使用设备代号及统一替换的 MAC。课程原件、个人报告、全部图片、原始工程与原始记录保存在本地。

## 拓扑与发包

端口按课件第 7 页，E1、E2、E3 分别表示 Ethernet0/0/1、0/0/2、0/0/3。

| 设备 | E1 | E2 | E3 |
| --- | --- | --- | --- |
| SW1 | Client1 | SW2 E1 | Client2 |
| SW2 | SW1 E2 | SW3 E1 | Client3 |
| SW3 | SW2 E2 | Client5 | Client4 |

各 Client 使用自身的 Ethernet0/0/1 接口。PC1～PC5 与任务文字中的 Client1～Client5 按序对应。发包顺序为 1→5、2→4、3→5、4→3、5→4。源 MAC 对应发送方，目的 MAC 对应接收方。

## 运行脚本

在仓库根目录运行，下列 `python` 指向本机可用的 Python 3。

```powershell
python .\exp2\scripts\switch_model.py
python .\exp2\scripts\prepare_topology.py
python -m unittest discover -s .\exp2\scripts -p 'test_*.py' -v
```

推导输出保存在 `local/model/`，拓扑XML输出到 `local/topology/`。模型 PCAP 使用 `02:00:00:00:00:01`～`05`、文档用 IP 和带 MODEL 标识的负载。

采集脚本是配套辅助工具。它通过 eNSP 的 Console 下发课件中的配置命令，保存实际设备输出；实验内容仍是五次发包、逐步 MAC 表和抓包分析。

在 eNSP 中启动三台交换机，等待 Console 出现命令提示符。保持 eNSP 开启，在仓库根目录执行初始配置、清表并采集第 0 步：

```powershell
python .\exp2\scripts\collect_switches.py --prepare --step 0
```

脚本适配 Console 分页，自动用空格续页；执行 `stp disable` 时自动回答该命令的确认问题。初始化后回读 MAC 表、老化时间和 STP 配置，核对空表、`Aging time: 0 seconds`、`stp disable` 后保存成功记录。手动配置使用 `config/SW1.txt`～`SW3.txt`，逐行执行，遇到 STP 的 `[Y/N]` 提示先输入 `y`，再继续。

五台 Client 参数和抓包窗口准备好后，在第 1 次正式发包前执行第 0 步，使整轮实验从空 MAC 表开始。

每完成一步发包，执行一次采集，`--step` 依次使用 1～5：

```powershell
python .\exp2\scripts\collect_switches.py --step 1
```

第 1～5 步只查询 MAC 表和老化时间，保留前面学到的表项。五次发送仍按 1→5、2→4、3→5、4→3、5→4 进行。

脚本连接本机 2000、2001、2002 三个 Console 端口。eNSP 如分配了其他端口，使用 `--ports 端口1 端口2 端口3`。原始记录保存在 `local/records/`。

离线提取实测抓包：

```powershell
python .\exp2\scripts\analyze_capture.py .\exp2\local\captures\SW2-SW3.pcap --output .\exp2\local\analysis\SW2-SW3
```

模型文件使用 `--kind 模型示例`。TShark 位于其他目录时，用 `--tshark` 指定路径。脚本兼容本机 TShark 1.4.3 的字段导出接口。

课程原件保留在原位置并纳入忽略规则，个人报告、原始记录和抓包集中保存在 `local/`。
