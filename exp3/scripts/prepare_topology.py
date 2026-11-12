"""生成两套独立的 eNSP 工程及参数表；校验模式只读，生成从不覆写。

PC 的 model/slot/settings 来自安装自带 examples/Campus_Network.topo。
S3700 的 slot 来自 examples/HCNA2.0 Lab 的 VLAN Configuration 工程。
这里只验证工程 XML 和课件映射；运行成功仍须在 eNSP 中现场验证。
"""
import argparse
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import uuid
import xml.etree.ElementTree as E

from lab_spec import EXPERIMENTS, STAGES, TOPOLOGY_FILES, expected_pc1, reference_configs, validate_spec

ROOT = Path(__file__).resolve().parents[1]
PC_DEFAULTS = (
    ("simpc_mc_dstip", "0.0.0.0"), ("simpc_mc_dstmac", "00-00-00-00-00-00"),
    ("simpc_dns1", "0.0.0.0"), ("simpc_dns2", "0.0.0.0"),
    ("simpc_ipv6", "::"), ("simpc_prefix", "128"), ("simpc_gatewayv6", "::"),
    ("simpc_dhcp_state", "0"), ("simpc_dhcpv6_state", "0"), ("simpc_dns_auto_state", "0"),
)


def pc_settings(experiment, name):
    host = EXPERIMENTS[experiment]["hosts"][name]
    # 两个工程使用不同的、虚构的本地管理 MAC，避免复用指导截图中的地址。
    mac = f'02-00-00-03-{int(experiment[-1]):02X}-{int(name[2:]):02X}'
    items = (("simpc_ip", host["ip"]), ("simpc_mask", host["mask"]),
             ("simpc_gateway", host["gateway"] or "0.0.0.0"), ("simpc_mac", mac)) + PC_DEFAULTS
    return " " + "  ".join(f"-{key} {value}" for key, value in items) + " "


def build_topology(experiment):
    validate_spec(experiment)
    spec = EXPERIMENTS[experiment]
    root = E.Element("topo", version="1.2.00.510")
    devices = E.SubElement(root, "devices")
    names = list(spec["switches"]) + list(spec["hosts"])
    # 每次新建批次使用新 ID，避免 eNSP 按旧设备目录复用运行缓存。
    ids = {name: str(uuid.uuid4()).upper() for name in names}
    for name in names:
        switch = name in spec["switches"]
        x, y = spec["positions"][name]
        dev = E.SubElement(devices, "dev", id=ids[name], name=name,
            model="S3700" if switch else "PC", settings="" if switch else pc_settings(experiment, name),
            com_port=str(spec["switches"][name]) if switch else "0", bootmode="0" if switch else "1",
            cx=f"{x:.6f}", cy=f"{y:.6f}", edit_left=str(x + 27), edit_top=str(y + 54))
        slot = E.SubElement(dev, "slot", number="slot17", isMainBoard="1")
        if switch:
            E.SubElement(slot, "interface", sztype="Ethernet", interfacename="Ethernet", count="22")
            E.SubElement(slot, "interface", sztype="Ethernet", interfacename="GE", count="2")
        else:
            E.SubElement(slot, "interface", sztype="Ethernet", interfacename="GE", count="1")
    lines = E.SubElement(root, "lines")
    for a, ap, b, bp in spec["links"]:
        line = E.SubElement(lines, "line", srcDeviceID=ids[a], destDeviceID=ids[b])
        E.SubElement(line, "interfacePair", lineName="Copper", srcIndex=str(ap - 1), tarIndex=str(bp - 1))
    E.SubElement(root, "shapes")
    E.SubElement(root, "txttips")
    validate_topology(root, experiment)
    E.indent(root, space="    ")
    return root


def read_topology(path):
    data = Path(path).read_bytes()
    text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8-sig")
    # 安装自带部分工程的声明使用非标准编码名 UNICODE，先解码再解析。
    return E.fromstring(re.sub(r"<\?xml[^>]*\?>", "", text, count=1))


def validate_topology(root, experiment, manifest=None):
    """严格校验设备、课件端口映射、端口占用、PC 参数与 Console；不修改 XML。"""
    spec = EXPERIMENTS[experiment]
    validate_spec(experiment)
    if root.tag != "topo":
        raise ValueError("不是 eNSP topo 根节点")
    devices = root.findall("./devices/dev")
    names = [d.get("name") for d in devices]
    ids = [d.get("id") for d in devices]
    wanted = set(spec["switches"]) | set(spec["hosts"])
    if set(names) != wanted or len(names) != len(wanted):
        raise ValueError("设备名称/数量与课件不一致，或名称重复")
    if not all(ids) or len(set(ids)) != len(ids):
        raise ValueError("设备 ID 缺失或重复")
    if manifest is not None:
        recorded = manifest.get("device_ids", {}).get(experiment)
        if recorded != {d.get("name"): d.get("id") for d in devices}:
            raise ValueError("设备 ID 与本批次 manifest 不一致")
    by_id = dict(zip(ids, devices))
    for d in devices:
        name = d.get("name")
        switch = name in spec["switches"]
        if d.get("model") != ("S3700" if switch else "PC"):
            raise ValueError(f"{name} 设备模型错误")
        if d.get("com_port") != (str(spec["switches"][name]) if switch else "0"):
            raise ValueError(f"{name} Console 端口与计划不符")
        slots = d.findall("slot")
        if len(slots) != 1 or slots[0].get("number") != "slot17" or slots[0].get("isMainBoard") != "1":
            raise ValueError(f"{name} 主板插槽结构错误")
        interfaces = [(i.get("sztype"), i.get("interfacename"), i.get("count")) for i in slots[0].findall("interface")]
        expected = [("Ethernet", "Ethernet", "22"), ("Ethernet", "GE", "2")] if switch else [("Ethernet", "GE", "1")]
        if interfaces != expected:
            raise ValueError(f"{name} 端口声明与原生模板不一致")
        if not switch:
            settings = dict(re.findall(r"-(simpc_\w+)\s+(\S+)", d.get("settings", "")))
            wanted_settings = dict(re.findall(r"-(simpc_\w+)\s+(\S+)", pc_settings(experiment, name)))
            if settings != wanted_settings:
                raise ValueError(f"{name} IPv4/原生 PC 参数不一致")
    used, actual = set(), set()
    for line in root.findall("./lines/line"):
        source, target = line.get("srcDeviceID"), line.get("destDeviceID")
        if source not in by_id or target not in by_id or source == target:
            raise ValueError("链路设备引用错误或自身回环")
        pairs = line.findall("interfacePair")
        if len(pairs) != 1 or pairs[0].get("lineName") != "Copper":
            raise ValueError("链路必须包含一对铜缆接口")
        pair = pairs[0]
        ends = []
        for device_id, key in ((source, "srcIndex"), (target, "tarIndex")):
            name = by_id[device_id].get("name")
            try:
                index = int(pair.get(key, ""))
            except ValueError as exc:
                raise ValueError("端口索引必须为整数") from exc
            limit = 22 if name in spec["switches"] else 1
            if not 0 <= index < limit:
                raise ValueError(f"{name} 端口索引越界")
            endpoint = (name, index + 1)
            if endpoint in used:
                raise ValueError(f"{name} 端口 {index + 1} 被复用")
            used.add(endpoint)
            ends.append(endpoint)
        actual.add(frozenset(ends))
    expected_edges = {frozenset(((a, ap), (b, bp))) for a, ap, b, bp in spec["links"]}
    if actual != expected_edges:
        raise ValueError("链路/端口映射与课件不一致")
    return {"experiment": experiment, "devices": len(devices), "links": len(actual), "status": "XML结构校验通过；eNSP运行待验证"}


def _write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def load_port_range_decision(decisions_path=None):
    """只读本地用户决策；缺少确认时维持内容1的配置门槛。"""
    path = Path(decisions_path) if decisions_path is not None else ROOT / "local" / "state" / "decisions.json"
    if not path.is_file():
        return {"status": "unresolved"}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("本地 decisions.json 必须为 JSON 对象")
    decision = data.get("port_range", {"status": "unresolved"})
    if not isinstance(decision, dict):
        raise ValueError("本地 port_range 决策必须为 JSON 对象")
    decision = dict(decision)
    if decision.get("status") == "confirmed":
        if decision.get("interface") != "Ethernet":
            raise ValueError("当前工程仅支持已确认的 Ethernet0/0/13—22 端口方案")
        if decision.get("source") != "user":
            raise ValueError("本次端口确认须记录实际来源 user")
    else:
        decision["status"] = "unresolved"
    return decision


def generate_bundle(output_root=None, config_root=None, run_id=None, decisions_path=None):
    output_root = Path(output_root) if output_root is not None else ROOT / "local" / "topology"
    run_id = run_id or datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid.uuid4().hex[:6]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", run_id):
        raise ValueError("run_id 仅允许字母、数字、下划线和减号")
    destination = output_root / run_id
    config_dir = Path(config_root) / run_id if config_root is not None else destination / "config"
    if destination.exists() or config_dir.exists():
        raise FileExistsError("输出批次已存在，拒绝覆写；请使用新的 run_id")
    port_decision = load_port_range_decision(decisions_path)
    port_confirmed = port_decision["status"] == "confirmed"
    built = {key: build_topology(key) for key in EXPERIMENTS}
    ids = [d.get("id") for root in built.values() for d in root.findall("./devices/dev")]
    if len(ids) != len(set(ids)):
        raise ValueError("两个独立工程之间设备 ID 冲突")
    destination.mkdir(parents=True, exist_ok=False)
    config_dir.mkdir(parents=True, exist_ok=False)
    files = {}
    for experiment, root in built.items():
        data = E.tostring(root, encoding="utf-8", xml_declaration=True)
        path = destination / TOPOLOGY_FILES[experiment]
        _write_new(path, data)
        files[path.name] = hashlib.sha256(data).hexdigest()
        buf = io.StringIO(newline="")
        writer = csv.writer(buf)
        writer.writerow(("host", "ip", "mask", "gateway", "switch", "switch_port", "pc_port", "vlan_after_config"))
        for name, host in EXPERIMENTS[experiment]["hosts"].items():
            writer.writerow((name, host["ip"], host["mask"], host["gateway"], host["switch"],
                             f'Ethernet0/0/{host["port"]}', "Ethernet0/0/1", host["vlan"]))
        _write_new(destination / f"{experiment}_pc_parameters.csv", buf.getvalue().encode("utf-8-sig"))
    for stage, switches in reference_configs().items():
        for name, commands in switches.items():
            heading = "# REFERENCE ONLY - NOT APPLIED TO ANY DEVICE\n"
            if stage == "part1-vlan2":
                heading += ("# CONFIRMED BY USER: ETHERNET0/0/13 THROUGH ETHERNET0/0/22\n" if port_confirmed else
                            "# CANDIDATE - DO NOT EXECUTE UNTIL THE ETHERNET/GE CONFLICT IS RESOLVED\n")
            _write_new(config_dir / stage / f"{name}.txt", (heading + "\n".join(commands) + "\n").encode("ascii"))
    stages = {stage: {**info, "pc1_theoretical": expected_pc1(stage)} for stage, info in STAGES.items()}
    if port_confirmed:
        stages["part1-vlan2"].pop("pending_decision", None)
        stages["part1-vlan2"]["description"] = "用户确认按P8/P10将Ethernet0/0/13—22配置为access VLAN2"
    port_resolution = ("用户确认：P11的GE为笔误；按P8图/P10命令使用Ethernet0/0/13—22。" if port_confirmed else
        "待定：P8图/P10命令使用Ethernet；P11写GE0/0/13—22。本批仅按P8/P10准备候选，不视为已确认。")
    manifest = {"kind": "eNSP拓扑准备，非实验结果", "created_local": datetime.now().astimezone().isoformat(),
        "runtime_verified": False, "files_sha256": files,
        "device_ids": {experiment: {d.get("name"): d.get("id") for d in root.findall("./devices/dev")}
                       for experiment, root in built.items()},
        "pc_schema_source": "安装自带 examples/Campus_Network/Campus_Network.topo；PC单口原生声明为Ethernet/GE",
        "port_resolution": port_resolution,
        "port_range_decision": port_decision,
        "pending_decisions": [] if port_confirmed else [{"id": "part1_interface_name", "status": "unresolved",
            "question": "请老师确认P11的GE0/0/13—22是否应为P8/P10的Ethernet0/0/13—22，以及应使用的交换机型号。",
            "gated_stage": "part1-vlan2"}],
        "reference_configs_enabled": False,
        "config_directory": str(config_dir.resolve()),
        "stages": stages}
    _write_new(destination / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
    decision_note = ("用户确认第11页GE为笔误，按P8/P10使用Ethernet0/0/13—22；确认来源为用户。\n" if port_confirmed else
        "内容1接口名待老师确认：P8/P10为Ethernet，P11为GE。part1-vlan2配置与连通矩阵为候选；确认前不执行该配置。\n")
    notes = ("本批文件是准备材料，尚未运行eNSP。\n"
        "两套工程按P8/P13的设备与连线生成，PC参数按P8/P14预填。\n"
        + decision_note +
        "config目录全部为未启用的CLI参考，生成过程不连接交换机。\n"
        "part2-access阶段的S1保持默认；part2-l2-optional是独立的可选验证设计；part2-routing为课件最终配置。\n"
        "CSV和manifest中的连通结论均为理论预期；真实ping、MAC表、ARP/ICMP抓包及截图须现场采集。\n")
    _write_new(destination / "preparation_notes.txt", notes.encode("utf-8"))
    return destination, config_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", type=Path, help="只读校验现有 .topo")
    parser.add_argument("--experiment", choices=EXPERIMENTS, help="与 --validate 一起使用")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--config-root", type=Path)
    parser.add_argument("--decisions", type=Path, help="只读决策文件；默认 local/state/decisions.json")
    args = parser.parse_args()
    if args.validate:
        if not args.experiment:
            parser.error("--validate 需要 --experiment")
        manifest_path = args.validate.parent / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
        print(json.dumps(validate_topology(read_topology(args.validate), args.experiment, manifest), ensure_ascii=False))
    else:
        if args.experiment:
            parser.error("生成模式同时准备两个独立工程，不使用 --experiment")
        destination, config = generate_bundle(args.output_root, args.config_root, decisions_path=args.decisions)
        print(f"已准备两套工程：{destination}\n通用参考配置：{config}\nXML结构校验通过；eNSP导入、运行和抓包待现场验证。")


if __name__ == "__main__":
    main()
