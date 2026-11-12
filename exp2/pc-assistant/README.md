# 交换机自学习实验助手

这里提供三台 S3700、五台原生 PC、七条链路的 eNSP 工程及助手源码。PC 地址为 `192.0.2.1`～`192.0.2.5`，MAC 使用虚构的本地管理地址。Console 端口为 2120、2121、2122。

## 准备独立运行副本

需要 Windows、Python 3.10 或更新版本、已安装的 eNSP 和 Wireshark。`python` 应在 PATH 中可用。

在仓库根目录执行：

```powershell
python -X utf8 .\exp2\pc-assistant\build_copy.py
```

生成器会显示 `exp2/local/pc-assistant/批次/` 的具体位置，每次创建新的设备 ID，保留既有工程。公开工程仅带拓扑 XML 和 PC 参数；交换机由 eNSP 初始化，助手再下发实验配置。

在 eNSP 打开生成目录内的 `交换机自学习_简化版.topo`，启动全部设备。双击同目录的 `检查启动.cmd` 可以只检查工程和 Python；正式运行使用 `开始实验.cmd`。入口需要与 eNSP 一致的权限，以便填写 PC 的 UDP 工具。

## 现场操作

1. 打开 Client1～Client5，均切到“UDP发包工具”，保持窗口打开。
2. 在七条链路分别右键开始抓包，每条一份；已经在运行的抓包可沿用。链路为 Client1—SW1、Client2—SW1、SW1—SW2、Client3—SW2、SW2—SW3、Client4—SW3、Client5—SW3。
3. 回到助手按提示确认。助手填写并回读地址、端口 1、IPv4 长度 29、数据 01～05，关闭周期发送和 VLAN 标记；初始化交换机后，依次发送 1→5、2→4、3→5、4→3、5→4。
4. 每步只发送一次并核对计数，采集三台交换机的完整 MAC 表；差异或超时会停止后续发送。
5. 五步完成后，按提示在七个 Wireshark 窗口停止抓包，保持窗口打开，再确认归档。助手保留原始抓包，并提取本轮新增帧。

实验记录位于运行副本的 `records/批次/`，日志在 `logs/`。两者均位于本地忽略目录。结果包含 JSON、CSV、实测说明和 HTML 总览；核对条件未齐备时保留相应待核查项。

抓包识别适配旧版 Wireshark 的 `wireshark…a进程号` 临时文件名。其他版本可将停止后的七份 Ethernet PCAP 分别保存到本轮 `captures/`，以链路名命名，例如 `Client1-SW1.pcap`；再运行 `重新核对抓包.cmd`。

## 本地报告

报告填充脚本另外需要 `python-docx`，以及用户自己保存的课程报告底稿副本。底稿须保留“主机”“SW1地址”“出现该帧的链路”表格及“拓扑及抓包图：”锚点。四张现场截图放在本轮 `screenshots/`，分别命名为 `01-拓扑.png`、`02-泛洪.png`、`03-单播.png`、`04-本地转发.png`。

在生成的运行副本中执行以下命令，将占位值换成已确认的信息：

```powershell
python -X utf8 .\整理报告.py --template "本地底稿副本.docx" --student-id "学号" --name "姓名"
```

实测核对通过且截图齐备后，脚本另存 `实验2-学号-姓名.docx`。底稿保持原样，完成版在本地用 Word 检查封面、图片和分页。

## 验证范围

公开工程已校验设备、端口、连线和地址对应关系；本地既有仿真实测对应的脱敏数据见 [实测资料](../evidence/README.md)。替换标识后的公开工程需在使用者自己的 eNSP 中导入运行。

```powershell
python -X utf8 -m unittest discover -s .\exp2\pc-assistant\tests -p 'test_*.py' -v
```

测试中的临时 PCAP 与窗口控件替身为测试夹具。
