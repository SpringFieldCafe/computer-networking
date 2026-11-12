"""离线分析实验3的真实抓包；结果只写入本地忽略目录，不发起采集或网络请求。"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_ROOT = ROOT / "exp3" / "local" / "analysis"
CHINA = timezone(timedelta(hours=8))
# 左侧是稳定的输出列名；只请求当前 TShark 字典中实际存在的字段。
FIELD_ALIASES = {
    "frame.number": ("frame.number",),
    "frame.time_relative": ("frame.time_relative",),
    "eth.src": ("eth.src",), "eth.dst": ("eth.dst",),
    "eth.type": ("eth.type",), "vlan.id": ("vlan.id",),
    "arp.opcode": ("arp.opcode",),
    "arp.src.proto_ipv4": ("arp.src.proto_ipv4",),
    "arp.dst.proto_ipv4": ("arp.dst.proto_ipv4",),
    "arp.src.hw_mac": ("arp.src.hw_mac",),
    "arp.dst.hw_mac": ("arp.dst.hw_mac",),
    "ip.src": ("ip.src",), "ip.dst": ("ip.dst",), "ip.ttl": ("ip.ttl",),
    "icmp.type": ("icmp.type",), "icmp.code": ("icmp.code",),
    "icmp.ident": ("icmp.ident", "icmp.id"),
    "icmp.seq": ("icmp.seq", "icmp.sequence_number"),
}
FIELDS = tuple(FIELD_ALIASES)
HOSTS = {
    "192.168.100.1": {"name": "PC1", "vlan": 100},
    "192.168.200.2": {"name": "PC2", "vlan": 200},
    "192.168.100.3": {"name": "PC3", "vlan": 100},
    "192.168.200.4": {"name": "PC4", "vlan": 200},
    "192.168.100.254": {"name": "S1 Vlanif100", "vlan": 100},
    "192.168.200.254": {"name": "S1 Vlanif200", "vlan": 200},
}
RELATIONS = {"same_vlan": "同VLAN（按课程地址配置）",
             "cross_vlan": "跨VLAN（按课程地址配置）", "unknown": "VLAN关系待补"}


class AnalysisError(RuntimeError):
    """带本地诊断目录的分析错误。"""


def now():
    return datetime.now(CHINA).isoformat(timespec="microseconds")


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def resolve_tshark(value=None):
    if value:
        located = shutil.which(str(value))
        candidate = Path(located or value).expanduser().resolve()
        if not candidate.is_file():
            raise AnalysisError("找不到 TShark；请用 --tshark 指定已有的 tshark.exe。")
        return candidate
    candidates = [shutil.which("tshark"),
                  "C:/Program Files/Wireshark/tshark.exe",
                  "C:/Program Files (x86)/Wireshark/tshark.exe"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise AnalysisError("未发现 TShark；请安装 Wireshark，或用 --tshark 指定 tshark.exe。")


def create_run_directory():
    # 先验证忽略规则，再写入包含原始地址和来源路径的分析结果。
    check_path = ANALYSIS_ROOT / ".privacy-check"
    try:
        check = subprocess.run(["git", "check-ignore", "--quiet", "--", str(check_path)],
                               cwd=ROOT, capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AnalysisError("无法验证本地分析目录的 Git 忽略规则，尚未写入结果。") from exc
    if check.returncode != 0:
        raise AnalysisError("exp3/local/analysis 未被 Git 忽略，尚未写入结果；请先补充忽略规则。")
    ANALYSIS_ROOT.mkdir(parents=True, exist_ok=True)
    # 不覆盖旧结果。极少见的同一微秒冲突直接报错，由调用者重新运行。
    output = ANALYSIS_ROOT / datetime.now(CHINA).strftime("%Y%m%dT%H%M%S.%f+0800")
    output.mkdir(exist_ok=False)
    return output


def run_tool(command, cwd, output, label, metadata, timeout):
    record = {"name": label, "argv": [str(x) for x in command],
              "cwd": str(cwd), "started_at": now()}
    metadata["commands"].append(record)
    try:
        completed = subprocess.run(command, cwd=cwd, capture_output=True,
                                   check=False, timeout=timeout)
        stdout, stderr = completed.stdout, completed.stderr
        record["returncode"] = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        record.update(returncode=None, error=f"超过 {timeout} 秒")
    except OSError as exc:
        stdout, stderr = b"", str(exc).encode("utf-8")
        record.update(returncode=None, error=str(exc))
    record["finished_at"] = now()
    record["stdout_file"] = f"{label}-stdout.txt"
    record["stderr_file"] = f"{label}-stderr.txt"
    (output / record["stdout_file"]).write_bytes(stdout)
    (output / record["stderr_file"]).write_bytes(stderr)
    write_json(output / "运行记录.json", metadata)
    if record["returncode"] != 0:
        raise AnalysisError(f"TShark {label} 失败（{record.get('error', '退出码 ' + str(record['returncode']))}）；"
                            f"请查看 {label}-stderr.txt。")
    return stdout


def select_fields(dictionary):
    available = set()
    for line in dictionary.decode("utf-8-sig", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            available.add(parts[2])
    if not available:
        raise AnalysisError("TShark 字段字典为空或格式异常；请查看 fields 的标准输出与错误文件。")
    selected = {canonical: next((alias for alias in aliases if alias in available), None)
                for canonical, aliases in FIELD_ALIASES.items()}
    if not selected["frame.number"]:
        raise AnalysisError("TShark 缺少 frame.number 字段，无法可靠统计抓包帧数。")
    return selected


def ascii_temporary_directory(temp_root=None):
    if temp_root is not None:
        candidates = [Path(temp_root).expanduser().resolve()]
    else:
        candidates = [Path(tempfile.gettempdir())]
        if os.name == "nt":
            candidates.extend([Path(os.environ.get("SystemRoot", "C:/Windows")) / "Temp",
                               Path(os.environ.get("PUBLIC", "C:/Users/Public"))])
        else:
            candidates.append(Path("/tmp"))
    for root in dict.fromkeys(candidates):
        root = root.resolve()
        if not str(root).isascii() or not root.is_dir():
            continue
        try:
            return tempfile.TemporaryDirectory(prefix="exp3-capture-", dir=root)
        except OSError:
            continue
    raise AnalysisError("未找到可写的纯英文临时目录；请用 --temp-root 指定已有的纯英文目录。")


def parse_export(raw, selected):
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    expected = [field for field in selected.values() if field]
    if reader.fieldnames is None:
        # 老版 TShark 对零帧 PCAP 可直接输出空串；调用成功且无内容时记录零帧。
        return [], ["TShark 成功退出且字段输出为空，按零帧记录。"]
    missing_headers = set(expected) - set(reader.fieldnames)
    if missing_headers:
        raise AnalysisError("字段导出缺少已请求的表头：" + ", ".join(sorted(missing_headers)))
    rows = []
    for line, record in enumerate(reader, start=2):
        if None in record or any(record.get(field) is None for field in expected):
            raise AnalysisError(f"字段 CSV 第 {line} 行列数异常，请检查 export-stdout.txt。")
        row = {canonical: (record.get(field, "") if field else "")
               for canonical, field in selected.items()}
        if not row["frame.number"].isdigit():
            raise AnalysisError(f"字段 CSV 第 {line} 行的 frame.number 无效。")
        rows.append(row)
    return rows, []


def integer(value):
    try:
        # 有些旧字段以十六进制导出，十进制前导零同样可接受。
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except (ValueError, AttributeError):
        return None


def vlan_relation(source, destination, scenario):
    if scenario != "inter-vlan" or source not in HOSTS or destination not in HOSTS:
        return "unknown"
    return "same_vlan" if HOSTS[source]["vlan"] == HOSTS[destination]["vlan"] else "cross_vlan"


def summarize(rows, selected, scenario, notes=None, kind="实测抓包"):
    counts = Counter({key: 0 for key in ["icmp_echo_requests", "icmp_echo_replies", "other_icmp",
                                        "arp_requests", "arp_replies", "other_arp"]})
    echo_groups, arp_groups = {}, {}
    pending_echo, pending_arp = defaultdict(deque), defaultdict(deque)
    echo_pairs, arp_pairs = [], []
    gaps = list(notes or [])
    missing = [name for name, value in selected.items() if value is None]
    if missing:
        gaps.append("本机字段字典缺项：" + "、".join(missing) + "；对应 CSV 列保留空值。")
    no_identity = 0
    invalid_echo = 0
    for row in rows:
        icmp_type = integer(row["icmp.type"])
        if icmp_type in (0, 8):
            counts["icmp_echo_requests" if icmp_type == 8 else "icmp_echo_replies"] += 1
            source, target = row["ip.src"], row["ip.dst"]
            if icmp_type == 0:
                source, target = target, source
            key = (source, target)
            group = echo_groups.setdefault(key, {"requester": source, "target": target,
                "vlan_relation": vlan_relation(source, target, scenario),
                "request_frames": [], "reply_frames": [], "matched_pairs": 0,
                "ethernet_pairs": Counter(), "observed_ttls": Counter()})
            group["request_frames" if icmp_type == 8 else "reply_frames"].append(row["frame.number"])
            if row["eth.src"] and row["eth.dst"]:
                group["ethernet_pairs"][(row["eth.src"], row["eth.dst"])] += 1
            if row["ip.ttl"]:
                group["observed_ttls"][row["ip.ttl"]] += 1
            ident, sequence = integer(row["icmp.ident"]), integer(row["icmp.seq"])
            # type=8/0 且 code=0 才是本工具关联的标准 Echo；多值或缺地址留在计数中。
            if integer(row["icmp.code"]) != 0:
                invalid_echo += 1
                continue
            if not source or not target or "," in source or "," in target or ident is None or sequence is None:
                no_identity += 1
                continue
            match_key = (*key, ident, sequence)
            if icmp_type == 8:
                pending_echo[match_key].append(row)
            elif pending_echo[match_key]:
                request = pending_echo[match_key].popleft()
                echo_pairs.append({"requester": source, "target": target, "identifier": ident,
                    "sequence": sequence, "request_frame": request["frame.number"],
                    "reply_frame": row["frame.number"]})
                group["matched_pairs"] += 1
        elif row["icmp.type"]:
            counts["other_icmp"] += 1
        opcode = integer(row["arp.opcode"])
        if opcode in (1, 2):
            counts["arp_requests" if opcode == 1 else "arp_replies"] += 1
            source, target = row["arp.src.proto_ipv4"], row["arp.dst.proto_ipv4"]
            if opcode == 2:
                source, target = target, source
            key = (source, target)
            group = arp_groups.setdefault(key, {"requester_ip": source, "target_ip": target,
                "vlan_relation": vlan_relation(source, target, scenario),
                "request_frames": [], "reply_frames": [], "matched_pairs": 0,
                "reply_mappings": Counter()})
            group["request_frames" if opcode == 1 else "reply_frames"].append(row["frame.number"])
            if opcode == 2 and row["arp.src.proto_ipv4"] and row["arp.src.hw_mac"]:
                group["reply_mappings"][(row["arp.src.proto_ipv4"], row["arp.src.hw_mac"])] += 1
            requester_mac = row["arp.src.hw_mac"] if opcode == 1 else row["arp.dst.hw_mac"]
            if not source or not target or not requester_mac:
                continue
            match_key = (*key, requester_mac.lower())
            if opcode == 1:
                pending_arp[match_key].append(row)
            elif pending_arp[match_key]:
                request = pending_arp[match_key].popleft()
                arp_pairs.append({"requester_ip": source, "target_ip": target,
                    "request_frame": request["frame.number"], "reply_frame": row["frame.number"],
                    "resolved_mac": row["arp.src.hw_mac"]})
                group["matched_pairs"] += 1
        elif row["arp.opcode"]:
            counts["other_arp"] += 1
    for group in echo_groups.values():
        group["ethernet_pairs"] = [{"source": a, "destination": b, "frames": count}
                                   for (a, b), count in sorted(group["ethernet_pairs"].items())]
        group["observed_ttls"] = dict(sorted(group["observed_ttls"].items()))
        group["unpaired_request_frames"] = len(group["request_frames"]) - group["matched_pairs"]
        group["unpaired_reply_frames"] = len(group["reply_frames"]) - group["matched_pairs"]
        if group["unpaired_request_frames"] or group["unpaired_reply_frames"]:
            gaps.append(f"ICMP {group['requester'] or '源IP缺项'} → {group['target'] or '目标IP缺项'}："
                        f"待关联请求/应答帧数 {group['unpaired_request_frames']}/{group['unpaired_reply_frames']}。")
    for group in arp_groups.values():
        group["reply_mappings"] = [{"ip": ip, "mac": mac, "frames": count}
                                   for (ip, mac), count in sorted(group["reply_mappings"].items())]
        group["unpaired_request_frames"] = len(group["request_frames"]) - group["matched_pairs"]
        group["unpaired_reply_frames"] = len(group["reply_frames"]) - group["matched_pairs"]
        if group["unpaired_request_frames"] or group["unpaired_reply_frames"]:
            gaps.append(f"ARP {group['requester_ip'] or '源IP缺项'} → {group['target_ip'] or '目标IP缺项'}："
                        f"待关联请求/应答帧数 {group['unpaired_request_frames']}/{group['unpaired_reply_frames']}。")
    if no_identity:
        gaps.append(f"{no_identity} 帧 Echo 缺少唯一的源/目的地址、标识符或序号，保留计数，待补关联依据。")
    if invalid_echo:
        gaps.append(f"{invalid_echo} 帧 Echo 类型帧的 code 缺失或非0，保留计数，待补标准 Echo 关联依据。")
    if not rows:
        gaps.append("本次输入解析得到0帧。")
    for field, label in [("icmp_echo_requests", "ICMP Echo请求"), ("icmp_echo_replies", "ICMP Echo应答"),
                         ("arp_requests", "ARP请求"), ("arp_replies", "ARP应答")]:
        if counts[field] == 0:
            gaps.append(f"{label}证据缺项：本次抓包中识别为0帧。")
    vlan_ids = Counter(value for row in rows for value in row["vlan.id"].split(",") if value)
    if not vlan_ids:
        gaps.append("802.1Q标签证据缺项：vlan.id 无非空值。接入口通常为无标签帧；配置映射见独立归类依据。")
    unknown = sum(group["vlan_relation"] == "unknown" for group in echo_groups.values())
    if unknown:
        gaps.append(f"{unknown} 组 Echo 端点缺少 VLAN 配置映射，关系标为 unknown。")
    evidence = {}
    families = {
        "ethernet": (lambda r: bool(r["eth.src"] or r["eth.dst"]), ("eth.src", "eth.dst", "eth.type")),
        "icmp": (lambda r: bool(r["icmp.type"]), ("ip.src", "ip.dst", "ip.ttl", "icmp.type", "icmp.code", "icmp.ident", "icmp.seq")),
        "arp": (lambda r: bool(r["arp.opcode"]), ("arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "arp.src.hw_mac", "arp.dst.hw_mac")),
    }
    for family, (predicate, fields) in families.items():
        relevant = [row for row in rows if predicate(row)]
        evidence[family] = {"identified_frames": len(relevant),
                            "blank_values": {field: sum(not row[field] for row in relevant) for field in fields}}
    return {"data_kind": kind, "scenario": scenario, "total_frames": len(rows),
            "configured_scenario": ({"initial_vlan": 1, "vlan2_ports": "Ethernet13–Ethernet22"}
                                    if scenario == "port-vlan" else
                                    {"trunks": "S1–S2、S1–S3", "allowed_vlans": [100, 200],
                                     "ipv4_prefix_length": 24} if scenario == "inter-vlan" else {}),
            "protocol_counts": dict(counts), "selected_fields": selected, "missing_fields": missing,
            "observed_vlan_ids": dict(sorted(vlan_ids.items())),
            "vlan_relation_basis": ("仅按实验3第二部分已知PC/网关地址配置归类；802.1Q标签另列为实际可见字段。"
                                    if scenario == "inter-vlan" else "未提供端点到VLAN的映射；保留实际标签，端点关系标为unknown。"),
            "configured_hosts": HOSTS if scenario == "inter-vlan" else {},
            "icmp_echo_groups": list(echo_groups.values()), "icmp_echo_pairs": echo_pairs,
            "icmp_pairing_basis": "同一抓包内，按反向IPv4地址、code=0、标识符、序号及先请求后应答逐一关联。",
            "arp_groups": list(arp_groups.values()), "arp_pairs": arp_pairs,
            "arp_pairing_basis": "按反向协议地址、请求方硬件地址及先请求后应答逐一关联；ARP无事务标识。",
            "field_evidence": evidence, "evidence_gaps": gaps}


def render_summary(summary):
    counts = summary["protocol_counts"]
    lines = [f"# {summary['data_kind']}：离线解析结果", "", f"解析帧数：{summary['total_frames']}。",
             f"ICMP Echo请求 {counts['icmp_echo_requests']} 帧，应答 {counts['icmp_echo_replies']} 帧；"
             f"ARP请求 {counts['arp_requests']} 帧，应答 {counts['arp_replies']} 帧。", "",
             summary["vlan_relation_basis"], "",
             "实际观察的 VLAN 标签：" + (json.dumps(summary["observed_vlan_ids"], ensure_ascii=False)
                                          if summary["observed_vlan_ids"] else "无非空值") + "。", "",
             "## ICMP Echo证据", "",
             "| 请求源IP | 目标IP | 配置归类 | 请求帧号 | 应答帧号 | 关联对数 |", "|---|---|---|---|---|---|"]
    for group in summary["icmp_echo_groups"]:
        lines.append(f"| {group['requester'] or '缺项'} | {group['target'] or '缺项'} | "
                     f"{RELATIONS[group['vlan_relation']]} | {','.join(group['request_frames']) or '缺项'} | "
                     f"{','.join(group['reply_frames']) or '缺项'} | {group['matched_pairs']} |")
    lines.extend(["", summary["icmp_pairing_basis"], "", "## ARP证据", "",
                  "| 请求方IP | 目标IP | 请求帧号 | 应答帧号 | 关联对数 |", "|---|---|---|---|---|"])
    for group in summary["arp_groups"]:
        lines.append(f"| {group['requester_ip'] or '缺项'} | {group['target_ip'] or '缺项'} | "
                     f"{','.join(group['request_frames']) or '缺项'} | {','.join(group['reply_frames']) or '缺项'} | "
                     f"{group['matched_pairs']} |")
    lines.extend(["", summary["arp_pairing_basis"], "", "## 证据缺项", ""])
    lines.extend("- " + gap for gap in summary["evidence_gaps"])
    if not summary["evidence_gaps"]:
        lines.append("所需协议类别与字段均有记录；逐帧原值见字段.csv，匹配关系见汇总.json。")
    return "\n".join(lines) + "\n"


def analyze(capture, tshark=None, scenario="inter-vlan", timeout=120, temp_root=None, kind="实测抓包"):
    if scenario not in ("inter-vlan", "port-vlan", "auto"):
        raise AnalysisError("未知实验场景。")
    if timeout <= 0:
        raise AnalysisError("超时时间须大于0。")
    if kind not in ("实测抓包", "测试夹具"):
        raise AnalysisError("数据类别须为实测抓包或测试夹具。")
    capture = Path(capture).expanduser().resolve()
    if not capture.is_file():
        raise AnalysisError("请提供已保存的 PCAP/PCAPNG 抓包文件。")
    output = create_run_directory()
    metadata = {"status": "running", "started_at": now(), "output": str(output),
                "source": {"path": str(capture)}, "scenario": scenario, "data_kind": kind,
                "python_version": sys.version, "commands": []}
    try:
        stat = capture.stat()
        metadata["source"].update(size_bytes=stat.st_size,
                                  modified_at=datetime.fromtimestamp(stat.st_mtime, CHINA).isoformat(),
                                  sha256=digest(capture))
        binary = resolve_tshark(tshark)
        metadata["tshark"] = str(binary)
        version = run_tool([str(binary), "-v"], ROOT, output, "version", metadata, timeout)
        metadata["tshark_version"] = version.decode("utf-8", errors="replace").splitlines()[0]
        dictionary = run_tool([str(binary), "-G", "fields"], ROOT, output, "fields", metadata, timeout)
        selected = select_fields(dictionary)
        metadata["selected_fields"] = selected
        with ascii_temporary_directory(temp_root) as temporary:
            temp = Path(temporary).resolve()
            # 旧版 Windows TShark 使用窄字符文件路径；运行目录和文件名都采用ASCII。
            copied = temp / "input.pcap"
            shutil.copyfile(capture, copied)
            copied_hash = digest(copied)
            metadata["parsed_input_sha256"] = copied_hash
            if copied_hash != metadata["source"]["sha256"]:
                raise AnalysisError("复制时源文件发生变化，请先停止写入抓包文件后重试。")
            command = [str(binary), "-n", "-r", "input.pcap", "-T", "fields",
                       "-E", "header=y", "-E", "separator=,", "-E", "quote=d"]
            for field in selected.values():
                if field:
                    command.extend(["-e", field])
            raw = run_tool(command, temp, output, "export", metadata, timeout)
        rows, notes = parse_export(raw, selected)
        with (output / "字段.csv").open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        summary = summarize(rows, selected, scenario, notes, kind)
        write_json(output / "汇总.json", summary)
        (output / "汇总.md").write_text(render_summary(summary), encoding="utf-8")
        metadata.update(status="success", finished_at=now(), total_frames=len(rows))
        write_json(output / "运行记录.json", metadata)
        return output, summary
    except Exception as exc:
        metadata.update(status="failed", finished_at=now(), error=f"{type(exc).__name__}: {exc}")
        write_json(output / "运行记录.json", metadata)
        (output / "错误.txt").write_text(str(exc) + "\n", encoding="utf-8")
        raise AnalysisError(f"{exc}\n诊断目录：{output}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "输出自动新建于 exp3/local/analysis/时间戳+0800/；保留源文件。"
        "port-vlan 对应端口VLAN实验，inter-vlan 对应既定100/200地址拓扑，auto 不作配置归类。"))
    parser.add_argument("capture", type=Path, help="已保存的真实抓包文件（支持中文路径）")
    parser.add_argument("--tshark", type=Path, help="TShark 程序路径；默认自动查找")
    parser.add_argument("--scenario", choices=("inter-vlan", "port-vlan", "auto"),
                        default="inter-vlan", help="VLAN归类所依据的课程场景，默认 inter-vlan")
    parser.add_argument("--timeout", type=float, default=120, help="每条 TShark 命令的超时秒数（默认120）")
    parser.add_argument("--temp-root", type=Path, help="兼容旧版TShark的已有ASCII临时目录")
    parser.add_argument("--kind", choices=("实测抓包", "测试夹具"), default="实测抓包",
                        help="输出中标明数据来源类别；人工构造PCAP请选测试夹具")
    args = parser.parse_args(argv)
    try:
        output, summary = analyze(args.capture, args.tshark, args.scenario, args.timeout, args.temp_root, args.kind)
    except (AnalysisError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    counts = summary["protocol_counts"]
    print(f"已解析 {summary['total_frames']} 帧；ICMP Echo请求/应答 "
          f"{counts['icmp_echo_requests']}/{counts['icmp_echo_replies']} 帧，ARP请求/应答 "
          f"{counts['arp_requests']}/{counts['arp_replies']} 帧。\n结果目录：{output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
