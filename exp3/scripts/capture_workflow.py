"""监听用户已开启的抓包，按检查点导出真实帧；从不启动抓包或操作 GUI。

PCAP/PCAPNG 解析与协议分析仅使用标准库。自动识别只接受进程 -i 命名管道
与明确的链路元数据；MAC 地址只注释主机身份，不用于猜测物理观察点。
所有原始副本、阶段窗口、映射及记录必须写入 Git 忽略的 local 目录。
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
              b"\x4d\x3c\xb2\xa1": ("<", 10**9), b"\xa1\xb2\x3c\x4d": (">", 10**9)}
SHB = b"\x0a\x0d\x0d\x0a"


class CaptureError(RuntimeError):
    """保留源文件和已存证据，要求调用者处理具体缺项。"""


class IncompleteCapture(CaptureError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalize_mac(value):
    value = re.sub(r"[^0-9a-f]", "", str(value).lower())
    return ":".join(value[n:n + 2] for n in range(0, 12, 2)) if len(value) == 12 else None


@dataclass
class Frame:
    number: int
    offset: int
    end: int
    packet: bytes
    wire_length: int
    timestamp_ticks: int | None
    timestamp_scale: int | None
    timestamp_offset: int = 0
    linktype: int = 1
    interface_id: int = 0
    context: tuple = ()


@dataclass
class ParsedCapture:
    data: bytes
    format: str
    frames: list[Frame]
    complete_end: int
    pending_bytes: int = 0
    metadata: list = field(default_factory=list)


def _options(data, endian):
    result = {}
    offset = 0
    while offset + 4 <= len(data):
        code, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        if offset + size > len(data):
            raise CaptureError("PCAPNG 选项越界。")
        result.setdefault(code, []).append(data[offset:offset + size])
        offset += (size + 3) & ~3
    return result


def parse_capture(data, *, allow_partial=False):
    """解析原始字节并保留帧偏移；allow_partial 仅忽略尚未写全的尾部。"""
    if len(data) < 4:
        raise IncompleteCapture("抓包文件头尚未写完。")
    if data[:4] in PCAP_MAGIC:
        if len(data) < 24:
            raise IncompleteCapture("PCAP 文件头尚未写完。")
        endian, scale = PCAP_MAGIC[data[:4]]
        major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHIIII", data, 4)
        if (major, minor) != (2, 4) or not snaplen:
            raise CaptureError("PCAP 文件头版本或截取长度异常。")
        # 新版 PCAP 的 network 高位可记录 FCS；低16位才是链路类型。
        linktype = network & 0xffff
        offset, frames = 24, []
        while offset < len(data):
            start = offset
            if offset + 16 > len(data):
                break
            sec, sub, caplen, wire = struct.unpack_from(endian + "IIII", data, offset)
            if caplen > snaplen or caplen > wire or sub >= scale:
                raise CaptureError(f"PCAP 第 {len(frames) + 1} 帧长度或时间戳异常。")
            if offset + 16 + caplen > len(data):
                break
            offset += 16 + caplen
            frames.append(Frame(len(frames) + 1, start, offset, data[start + 16:offset],
                                wire, sec * scale + sub, scale, linktype=linktype))
        pending = len(data) - offset
        if pending and not allow_partial:
            raise IncompleteCapture("PCAP 尾帧正在写入。")
        return ParsedCapture(data, "pcap", frames, offset, pending, [(0, 24, "header")])
    if data[:4] != SHB:
        raise CaptureError("仅支持 PCAP 或 PCAPNG 抓包。")
    offset, frames, metadata, contexts, interfaces = 0, [], [], [], []
    endian = None
    while offset < len(data):
        start = offset
        if len(data) - offset < 12:
            break
        is_shb = data[offset:offset + 4] == SHB
        if is_shb:
            bom = data[offset + 8:offset + 12]
            if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise CaptureError("PCAPNG 字节序标记异常。")
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        if endian is None:
            raise CaptureError("PCAPNG 缺少 section header。")
        kind, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or length % 4:
            raise CaptureError("PCAPNG block 长度异常。")
        if offset + length > len(data):
            break
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise CaptureError("PCAPNG block 首尾长度不一致。")
        end = offset + length
        body = data[offset + 8:end - 4]
        if is_shb:
            if length < 28:
                raise CaptureError("PCAPNG section header 过短。")
            if struct.unpack_from(endian + "H", body, 4)[0] != 1:
                raise CaptureError("PCAPNG section major version 非1。")
            interfaces = []
            contexts = [(start, end, "shb", endian)]
            metadata.append(contexts[0])
        elif kind == 1:
            if length < 20:
                raise CaptureError("PCAPNG interface block 过短。")
            linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
            options = _options(body[8:], endian)
            scale = 10**6
            if 9 in options and options[9][0]:
                resolution = options[9][0][0]
                scale = (2 ** (resolution & 127)) if resolution & 128 else 10**resolution
            tsoffset = 0
            if 14 in options and len(options[14][0]) == 8:
                tsoffset = struct.unpack(endian + "q", options[14][0])[0]
            interfaces.append((linktype, snaplen, scale, tsoffset))
            contexts.append((start, end, "idb", endian))
            metadata.append(contexts[-1])
        elif kind in (2, 3, 6):
            if kind in (2, 6):
                if len(body) < 20:
                    raise CaptureError("PCAPNG packet block 过短。")
                if kind == 6:
                    interface, high, low, caplen, wire = struct.unpack_from(endian + "IIIII", body)
                else:
                    interface, _, high, low, caplen, wire = struct.unpack_from(endian + "HHIIII", body)
                ticks = (high << 32) | low
                packet_offset = 20
            else:
                if len(body) < 4 or not interfaces:
                    raise CaptureError("PCAPNG simple packet 缺少长度或 interface。")
                interface, ticks, packet_offset = 0, None, 4
                wire = struct.unpack_from(endian + "I", body)[0]
                caplen = min(wire, interfaces[0][1] or wire)
            if interface >= len(interfaces):
                raise CaptureError("PCAPNG packet 引用未知 interface。")
            linktype, snaplen, scale, tsoffset = interfaces[interface]
            if caplen > wire or (snaplen and caplen > snaplen) or packet_offset + ((caplen + 3) & ~3) > len(body):
                raise CaptureError("PCAPNG packet 长度越界。")
            frames.append(Frame(len(frames) + 1, start, end, body[packet_offset:packet_offset + caplen],
                                wire, ticks, scale if ticks is not None else None, tsoffset,
                                linktype, interface, tuple(contexts)))
        else:
            # 非包元数据不承载流量，窗口只需 SHB/IDB；原始副本保留所有 block。
            metadata.append((start, end, "other", endian))
        offset = end
    if not metadata:
        raise IncompleteCapture("PCAPNG 文件头尚未写完。")
    pending = len(data) - offset
    if pending and not allow_partial:
        raise IncompleteCapture("PCAPNG 尾 block 正在写入。")
    return ParsedCapture(data, "pcapng", frames, offset, pending, metadata)


def capture_window(parsed, start_offset, end_offset=None):
    """只导出检查点后的完整包 block，保留帧字节和原始时间戳。"""
    end_offset = parsed.complete_end if end_offset is None else end_offset
    boundaries = {0, parsed.complete_end} | {f.offset for f in parsed.frames} | {f.end for f in parsed.frames}
    boundaries.update(item[1] for item in parsed.metadata)
    if start_offset not in boundaries or not 0 <= start_offset <= end_offset <= parsed.complete_end:
        raise CaptureError("窗口偏移不在完整记录边界。")
    selected = [f for f in parsed.frames if f.offset >= start_offset and f.end <= end_offset]
    if parsed.format == "pcap":
        return parsed.data[:24] + b"".join(parsed.data[f.offset:f.end] for f in selected), selected
    output, seen = [], set()
    contexts = [f.context for f in selected]
    if not contexts:
        # 零帧 PCAPNG 仍提供一个 section 及其 interface 描述。
        contexts = [tuple(item for item in parsed.metadata if item[2] in ("shb", "idb"))]
    for index, context in enumerate(contexts):
        for start, end, kind, endian in context:
            if (start, end) in seen:
                continue
            seen.add((start, end))
            block = parsed.data[start:end]
            if kind == "shb" and struct.unpack_from(endian + "q", block, 16)[0] != -1:
                # 仅 section 元数据长度改为标准的未知长度，包 block 全部逐字节复制。
                block = block[:16] + struct.pack(endian + "q", -1) + block[24:]
            output.append(block)
        if selected:
            f = selected[index]
            output.append(parsed.data[f.offset:f.end])
    return b"".join(output), selected


def decode_frame(frame):
    """提取 Ethernet/VLAN/ARP/IPv4/ICMP 原字段，不推演未观察的报文。"""
    packet = frame.packet
    row = {"source_frame": frame.number, "source_offset": frame.offset, "source_end": frame.end,
           "captured_length": len(packet), "wire_length": frame.wire_length,
           "timestamp_ticks": frame.timestamp_ticks, "timestamp_scale": frame.timestamp_scale,
           "timestamp_offset_seconds": frame.timestamp_offset, "interface_id": frame.interface_id,
           "linktype": frame.linktype}
    if frame.linktype != 1 or len(packet) < 14:
        row["parse_note"] = "非Ethernet或Ethernet头不完整"
        return row
    row.update(destination_mac=packet[:6].hex(":"), source_mac=packet[6:12].hex(":"))
    kind, offset, tags = struct.unpack_from("!H", packet, 12)[0], 14, []
    while kind in (0x8100, 0x88a8, 0x9100):
        if len(packet) < offset + 4:
            row["parse_note"] = "VLAN头不完整"
            return row
        tci, kind = struct.unpack_from("!HH", packet, offset)
        tags.append({"vlan": tci & 0xfff, "priority": tci >> 13, "dei": (tci >> 12) & 1})
        offset += 4
    row.update(ether_type=f"0x{kind:04x}", vlan_tags=tags)
    if kind == 0x0806 and len(packet) >= offset + 28:
        htype, ptype, hlen, plen, opcode = struct.unpack_from("!HHBBH", packet, offset)
        row.update(protocol="ARP", arp_opcode=opcode)
        if (htype, ptype, hlen, plen) == (1, 0x800, 6, 4):
            row.update(arp_source_mac=packet[offset + 8:offset + 14].hex(":"),
                       source_ip=str(ipaddress.IPv4Address(packet[offset + 14:offset + 18])),
                       arp_target_mac=packet[offset + 18:offset + 24].hex(":"),
                       destination_ip=str(ipaddress.IPv4Address(packet[offset + 24:offset + 28])))
    elif kind == 0x0800 and len(packet) >= offset + 20:
        ip = packet[offset:]
        ihl = (ip[0] & 15) * 4
        total = struct.unpack_from("!H", ip, 2)[0]
        if ip[0] >> 4 != 4 or ihl < 20 or total < ihl or len(ip) < ihl:
            row["parse_note"] = "IPv4头长度异常"
            return row
        fragment = struct.unpack_from("!H", ip, 6)[0]
        row.update(protocol="IPv4", source_ip=str(ipaddress.IPv4Address(ip[12:16])),
                   destination_ip=str(ipaddress.IPv4Address(ip[16:20])), ip_ttl=ip[8],
                   ip_protocol=ip[9], ip_total_length=total, ip_fragment_offset=fragment & 0x1fff,
                   ip_more_fragments=bool(fragment & 0x2000))
        if ip[9] == 1 and not fragment & 0x1fff and total >= ihl + 8 and len(ip) >= ihl + 8:
            icmp = ip[ihl:min(total, len(ip))]
            row.update(protocol="ICMP", icmp_type=icmp[0], icmp_code=icmp[1])
            if icmp[0] in (0, 8):
                ident, seq = struct.unpack_from("!HH", icmp, 4)
                row.update(icmp_id=ident, icmp_seq=seq, icmp_payload_hex=icmp[8:].hex(),
                           icmp_complete=len(ip) >= total and not fragment & 0x2000)
    return row


def analyze_frames(frames, hosts=None, kind="原始帧解析"):
    hosts = hosts or {}
    mac_hosts = {normalize_mac(h.get("mac")): name for name, h in hosts.items() if h.get("mac")}
    rows = [decode_frame(f) for f in frames]
    pending, pairs, arp_pending, arp_pairs = defaultdict(deque), [], defaultdict(deque), []
    for row in rows:
        for field_name in ("source_mac", "destination_mac"):
            if row.get(field_name) in mac_hosts:
                row[field_name + "_host"] = mac_hosts[row[field_name]]
        if row.get("icmp_type") in (0, 8) and row.get("icmp_code") == 0 and row.get("icmp_complete"):
            src, dst = row["source_ip"], row["destination_ip"]
            if row["icmp_type"] == 0:
                src, dst = dst, src
            key = (src, dst, row["icmp_id"], row["icmp_seq"], row["icmp_payload_hex"])
            if row["icmp_type"] == 8:
                pending[key].append(row)
            elif pending[key]:
                request = pending[key].popleft()
                pairs.append({"source_ip": src, "destination_ip": dst, "icmp_id": key[2], "icmp_seq": key[3],
                              "request_frame": request["source_frame"], "reply_frame": row["source_frame"]})
        if row.get("protocol") == "ARP" and "source_ip" in row:
            if row["arp_opcode"] == 1:
                key = (row["source_ip"], row["destination_ip"], row["arp_source_mac"])
                arp_pending[key].append(row)
            elif row["arp_opcode"] == 2:
                key = (row["destination_ip"], row["source_ip"], row["arp_target_mac"])
                if arp_pending[key]:
                    request = arp_pending[key].popleft()
                    arp_pairs.append({"source_ip": key[0], "destination_ip": key[1],
                                      "request_frame": request["source_frame"], "reply_frame": row["source_frame"]})
    counts = Counter(r.get("protocol", "other") for r in rows)
    return {"data_kind": kind, "total_frames": len(rows), "protocol_counts": dict(counts),
            "vlan_ids": sorted({tag["vlan"] for r in rows for tag in r.get("vlan_tags", [])}),
            "icmp_echo_pairs": pairs, "arp_pairs": arp_pairs, "frames": rows,
            "unmatched_echo_requests": [r["source_frame"] for queue in pending.values() for r in queue],
            "pairing_basis": "同一链路窗口内按反向IPv4、code=0、标识符、序号、完整负载及先请求后应答逐一关联"}


CAPTURE_PROCESS_NAMES = {"dumpcap.exe", "wireshark.exe", "ip_capture.exe"}


def capture_process_ancestors(metadata, capture_details):
    """从内存元数据表选取抓包进程及最多8层祖先，移除祖先的命令行。

    全进程表仅含ID/PPID/名称/出生时刻。CommandLine来自第二个仅限定三类
    抓包进程的查询；须与元数据的PID、名称、出生时刻一致才关联，避免PID复用。
    """
    table = {int(p["ProcessId"]): p for p in metadata}
    details = {int(p["ProcessId"]): p for p in capture_details
               if str(p.get("Name", "")).lower() in CAPTURE_PROCESS_NAMES}
    seeds = [pid for pid, p in table.items() if str(p.get("Name", "")).lower() in CAPTURE_PROCESS_NAMES]
    selected = set(seeds)
    for seed in seeds:
        current, visited = table[seed], {seed}
        for _ in range(8):
            parent_pid = int(current.get("ParentProcessId", 0))
            parent = table.get(parent_pid)
            if parent is None or parent_pid in visited:
                break
            # 父PID若已被较晚出生的进程复用，就不是本次捕获的真实祖先。
            try:
                child_time = datetime.fromisoformat(current["started_at"])
                parent_time = datetime.fromisoformat(parent["started_at"])
                if child_time.tzinfo is None or parent_time.tzinfo is None or parent_time > child_time:
                    break
            except (KeyError, TypeError, ValueError):
                break
            selected.add(parent_pid)
            visited.add(parent_pid)
            current = parent
    result = []
    for pid in sorted(selected):
        item = table[pid]
        safe = {key: item.get(key) for key in ("ProcessId", "ParentProcessId", "Name", "started_at")}
        detail = details.get(pid)
        if (detail and str(item.get("Name", "")).lower() in CAPTURE_PROCESS_NAMES
                and detail.get("Name", "").casefold() == item.get("Name", "").casefold()
                and detail.get("started_at") == item.get("started_at")):
            safe["CommandLine"] = detail.get("CommandLine")
        result.append(safe)
    return result


def running_capture_processes():
    """只读Windows进程元数据；仅抓包三类读取命令行，不读取cmd祖先命令行。"""
    if os.name != "nt":
        return []
    # 第一轮显式-Property不含CommandLine；全进程元数据仅在内存中用于向上找父链。
    # 第二轮查询严格限定抓包三类，绝不读取cmd.exe/eNSP_Client.exe的命令行。
    command = ("$ErrorActionPreference='Stop'; "
               "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
               "$captureMetadata=@(Get-CimInstance Win32_Process "
               "-Property ProcessId,ParentProcessId,Name,CreationDate | "
               "Select-Object ProcessId,ParentProcessId,Name,"
               "@{Name='started_at';Expression={if ($_.CreationDate) {$_.CreationDate.ToUniversalTime().ToString('o')}}}); "
               "$captureDetails=@(Get-CimInstance Win32_Process "
               "-Filter \"Name='dumpcap.exe' OR Name='Wireshark.exe' OR Name='IP_Capture.exe'\" "
               "-Property ProcessId,ParentProcessId,Name,CreationDate,CommandLine | "
               "Select-Object ProcessId,ParentProcessId,Name,CommandLine,"
               "@{Name='started_at';Expression={if ($_.CreationDate) {$_.CreationDate.ToUniversalTime().ToString('o')}}}); "
               "@{processes=$captureMetadata;capture_details=$captureDetails} | ConvertTo-Json -Depth 4 -Compress")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, timeout=15, check=False)
    if result.returncode:
        raise CaptureError("读取已有抓包进程失败；请提供明确的链路与文件映射。")
    raw = result.stdout.decode("utf-8-sig", errors="replace").strip()
    items = json.loads(raw) if raw else {}
    return capture_process_ancestors(items.get("processes", []), items.get("capture_details", []))


def command_option(command, option):
    # Windows 管道路径中的反斜杠必须按原样保留，不能用 POSIX shlex。
    match = re.search(r"(?:^|\s)" + re.escape(option) + r'(?:\s+|=)(?:"([^"]*)"|(\S+))', command or "")
    return (match.group(1) if match.group(1) is not None else match.group(2)) if match else None


def _path_key(path):
    return os.path.normcase(str(Path(path).expanduser().resolve()))


def interface_metadata(interface):
    """仅提取自描述的pipe字段；无标签的数字不推断为0基/1基端口。"""
    interface = interface or ""
    result = {}
    identities = re.findall(r"(?i)(?<![0-9a-f])([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![0-9a-f])", interface)
    if len(set(value.casefold() for value in identities)) == 1:
        result["device_id"] = identities[0]
    index = re.search(r"(?i)(?:^|[\\/;,_ -])port_index[=:](\d+)(?:$|[\\/;,_ -])", interface)
    name = re.search(r"(?i)(?<![a-z])((?:GigabitEthernet|Ethernet|GE)\d+/\d+/\d+)(?!\d)", interface)
    if index:
        result["port_index"] = int(index.group(1))
    if name:
        result["interface_name"] = name.group(1)
    return result


def discover_candidates(processes=None, temp_dir=None):
    processes = running_capture_processes() if processes is None else processes
    by_pid = {int(p.get("ProcessId", p.get("pid", 0))): p for p in processes}
    temporary = Path(temp_dir or tempfile.gettempdir())
    # 只枚举 Wireshark 临时文件名；映射确认前不打开任何抓包正文。
    files = list(temporary.glob("wireshark*")) if temporary.is_dir() else []
    result = []
    for pid, process in by_pid.items():
        name = process.get("Name", process.get("name", ""))
        if name.lower() != "dumpcap.exe":
            continue
        command = process.get("CommandLine", process.get("command_line", "")) or ""
        parent = by_pid.get(int(process.get("ParentProcessId", process.get("parent_pid", 0))), {})
        ancestor = parent
        helper = {}
        parent_command = ""
        ancestry, visited = [], {pid}
        for _ in range(8):
            ancestor_pid = int(ancestor.get("ProcessId", ancestor.get("pid", 0)))
            if not ancestor or ancestor_pid in visited:
                break
            visited.add(ancestor_pid)
            ancestor_name = str(ancestor.get("Name", ancestor.get("name", ""))).lower()
            ancestry.append({"pid": ancestor_pid, "name": ancestor.get("Name", ancestor.get("name", "")),
                             "started_at": ancestor.get("started_at")})
            if ancestor_name == "wireshark.exe" and not parent_command:
                parent_command = ancestor.get("CommandLine", ancestor.get("command_line", "")) or ""
            if ancestor_name == "ip_capture.exe":
                helper = ancestor
                break
            ancestor = by_pid.get(int(ancestor.get("ParentProcessId", ancestor.get("parent_pid", 0))), {})
            if not ancestor:
                break
        interface = command_option(command, "-i") or command_option(parent_command, "-i")
        direct = command_option(command, "-w")
        paths = [Path(direct)] if direct and Path(direct).is_absolute() and not direct.startswith("\\\\.\\pipe\\") else []
        paths.extend(p for p in files if re.fullmatch(r"wireshark.*a" + str(pid), p.name, re.I))
        for path in dict.fromkeys(paths):
            if path.is_file():
                result.append({"path": str(path.resolve()), "pid": pid, "interface": interface,
                               **interface_metadata(interface),
                               "started_at": process.get("started_at"),
                               "capture_helper_pid": helper.get("ProcessId", helper.get("pid")),
                               "capture_helper_started_at": helper.get("started_at"),
                               "capture_ancestry": ancestry,
                               "parent_pid": int(process.get("ParentProcessId", process.get("parent_pid", 0))),
                               "identity_basis": "活动dumpcap PID与-w或Wireshark临时文件PID关联"})
    return result


def _interface_matches(candidate, metadata, topology_id):
    """完整 pipe 或含明确拓扑/设备/端口字段的元数据；不按 MAC/模糊子串配链路。"""
    interface = candidate.get("interface") or ""
    if isinstance(metadata, str):
        metadata = {"interfaces": [metadata]}
    explicit = metadata.get("interfaces", metadata.get("interface", []))
    explicit = [explicit] if isinstance(explicit, str) else explicit
    if interface and any(interface.casefold() == str(value).casefold() for value in explicit):
        return True
    endpoints = metadata.get("endpoints", [])
    for endpoint in endpoints:
        device = str(endpoint.get("device_id", "")).strip("{}").casefold()
        actual_device = str(candidate.get("device_id", "")).strip("{}").casefold()
        if not device or actual_device != device:
            continue
        if topology_id and candidate.get("topology_id") not in (None, topology_id):
            continue
        # 完整设备UUID标识该工程的设备；仍须同时核对端口及端口编号约定。
        if ("port_index" in endpoint and "port_index" in candidate
                and str(endpoint["port_index"]) == str(candidate["port_index"])):
            return True
        if (endpoint.get("interface_name") and candidate.get("interface_name")
                and endpoint["interface_name"].casefold() == candidate["interface_name"].casefold()):
            return True
        if (endpoint.get("port") is not None and candidate.get("port") is not None
                and str(endpoint["port"]) == str(candidate["port"])):
            return True
    # 自动解析 pipe 字段有命名格式差异，只接受调用者已提取出的结构化字段。
    # 同一设备可属于多个工程，结构化匹配必须包含已确认拓扑 ID。
    expected_topology = metadata.get("topology_id") or topology_id
    return bool(expected_topology and candidate.get("topology_id") == expected_topology
                and metadata.get("device_id") and metadata.get("port") is not None
                and candidate.get("device_id") == metadata["device_id"]
                and str(candidate.get("port")) == str(metadata["port"]))


class CaptureSession:
    def __init__(self, required_links, hosts, output_dir, *, mapping=None, topology_id=None,
                 link_metadata=None, candidates=None, process_provider=None, retry_seconds=1.0,
                 kind="实测抓包", require_active=False):
        self.required_links = tuple(required_links)
        if not self.required_links or len(set(self.required_links)) != len(self.required_links):
            raise ValueError("required_links 须为非空且不重复的链路名列表。")
        self.hosts, self.output_dir = hosts, Path(output_dir).resolve()
        self.mapping, self.link_metadata = mapping or {}, link_metadata or {}
        self.topology_id, self.candidates = topology_id, candidates
        self.process_provider = process_provider
        self.retry_seconds = max(0, retry_seconds)
        if kind not in ("实测抓包", "测试夹具"):
            raise ValueError("kind 须为实测抓包或测试夹具。")
        self.kind = kind
        self.require_active = require_active
        self.sources, self.checkpoints = {}, {}
        self.last_checkpoint = None
        self._privacy_checked = False
        self._last_processes = None

    def _candidate_snapshot(self):
        if self.candidates is not None:
            return [dict(c) for c in (self.candidates() if callable(self.candidates) else self.candidates)]
        self._last_processes = self.process_provider() if self.process_provider else running_capture_processes()
        return discover_candidates(self._last_processes)

    def _active_pids(self, candidates):
        if self._last_processes is not None:
            return {int(p.get("ProcessId", p.get("pid", 0))) for p in self._last_processes
                    if str(p.get("Name", p.get("name", ""))).lower() == "dumpcap.exe"}
        return {int(c["pid"]) for c in candidates if c.get("pid") is not None}

    def _prepare_output(self):
        if self._privacy_checked:
            return
        try:
            self.output_dir.relative_to(ROOT)
        except ValueError as exc:
            raise CaptureError("抓包结果须保存到本仓库已忽略的 local 目录。") from exc
        if "local" not in self.output_dir.relative_to(ROOT).parts:
            raise CaptureError("抓包结果须保存到 local 目录。")
        check = subprocess.run(["git", "check-ignore", "--quiet", "--", str(self.output_dir / ".privacy-check")],
                               cwd=ROOT, capture_output=True, timeout=10, check=False)
        if check.returncode:
            raise CaptureError("输出目录未被 Git 忽略，尚未写入抓包结果。")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._privacy_checked = True

    def discover(self, mapping=None):
        if mapping is not None:
            self.mapping = mapping
        discovery_error = None
        try:
            candidates = self._candidate_snapshot()
        except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as exc:
            candidates, discovery_error = [], str(exc)
        chosen, missing, ambiguities = {}, [], {}
        for link in self.required_links:
            if self.mapping.get(link):
                value = self.mapping[link]
                source = dict(value) if isinstance(value, dict) else {"path": str(value)}
                if not source.get("path"):
                    missing.append(link)
                    continue
                matching = [c for c in candidates if _path_key(c["path"]) == _path_key(source["path"])]
                if self.require_active:
                    matching = [c for c in matching
                                if c.get("pid") is not None
                                and (source.get("pid") is None or c["pid"] == source["pid"])
                                and (not source.get("started_at") or c.get("started_at") == source["started_at"])]
                    if len(matching) != 1:
                        missing.append(link)
                        continue
                if source.get("enrollment_path") and not any(c.get("pid") == source.get("pid")
                                                              and c.get("started_at") == source.get("started_at")
                                                              for c in matching):
                    missing.append(link)
                    continue
                if len(matching) == 1:
                    source = {**matching[0], **source}
                source.setdefault("identity_basis", "用户明确的链路—文件映射")
            else:
                matches = [c for c in candidates if _interface_matches(c, self.link_metadata.get(link, {}), self.topology_id)]
                unique = {_path_key(c["path"]): c for c in matches}
                if len(unique) != 1:
                    missing.append(link)
                    if matches:
                        ambiguities[link] = list(unique)
                    continue
                source = dict(next(iter(unique.values())))
                source["identity_basis"] = "活动抓包接口与已确认链路元数据精确对应"
            path = Path(source["path"]).expanduser().resolve()
            if not path.is_file():
                missing.append(link)
                continue
            source.update(link=link, path=str(path))
            chosen[link] = source
        reverse = defaultdict(list)
        for link, source in chosen.items():
            reverse[_path_key(source["path"])].append(link)
        for path, links in reverse.items():
            if len(links) > 1:
                for link in links:
                    chosen.pop(link)
                    if link not in missing:
                        missing.append(link)
                    ambiguities[link] = ["同一文件被指定给多条链路", *links]
        self.sources = chosen
        result = {"status": "needs_input" if missing else "ready", "missing": missing,
                  "needs_input": bool(missing), "captures": list(chosen.values()), "ambiguities": ambiguities,
                  "candidates": candidates,
                  "mapping_template": {link: {"path": "请填写该链路当前抓包文件的完整路径"} for link in missing}}
        if discovery_error:
            result["discovery_error"] = discovery_error
        if missing:
            result["instruction"] = "请一次填写所有缺失链路的文件路径；若已知命名管道，也可提供接口与链路的准确对应。"
        return result

    def enroll_missing(self, timeout=90, progress=print, *, poll_interval=.2, settle_seconds=.6):
        """逐条提示用户在eNSP开始抓包，自动关联提示后唯一新捕获；不点GUI。

        本机eNSP的IP_Capture.exe以 `wireshark.exe -k -i -` 喂入匿名管道，
        命令行本身没有链路名。这里通过用户按指定链路执行的唯一新启动动作
        建立明确映射；旧未知抓包保持原样，两个并发新启动直接停止绑定。
        timeout 为每条链路等待秒数。进程父链、出生时刻及基线均归档到local。
        """
        if timeout <= 0 or poll_interval <= 0 or settle_seconds < 0:
            raise ValueError("等待时间及轮询间隔须为正，稳定等待时间须为非负。")
        discovery = self.discover()
        if not discovery["needs_input"]:
            return discovery
        self._prepare_output()
        enrollment_id = uuid.uuid4().hex
        journal = {"started_at": now(), "kind": "用户逐链路手动启动后的自动关联", "steps": []}
        journal_path = self.output_dir / f"capture-enrollment-{enrollment_id}.json"

        def finish(reason=None):
            journal["finished_at"] = now()
            if reason:
                journal["reason"] = reason
            write_json(journal_path, journal)
            result = self.discover()
            result["enrollment_path"] = str(journal_path)
            if reason:
                result["enrollment_reason"] = reason
                progress(reason)
            return result

        for link in list(discovery["missing"]):
            try:
                baseline = self._candidate_snapshot()
            except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as exc:
                return finish("读取抓包基线失败：" + str(exc))
            baseline_pids = self._active_pids(baseline)
            prompted_at = now()
            step = {"link": link, "prompted_at": prompted_at, "baseline_pids": sorted(baseline_pids),
                    "baseline_paths": [c["path"] for c in baseline], "status": "waiting"}
            journal["steps"].append(step)
            write_json(journal_path, journal)
            progress(f"现在请在 eNSP 中右键链路 {link} 开始抓包（只启动这一条，助手自动识别，无需保存或按回车）。")
            deadline, stable_pid, stable_since = time.monotonic() + timeout, None, None
            accepted = False
            while time.monotonic() < deadline:
                try:
                    current = self._candidate_snapshot()
                except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as exc:
                    return finish("读取新抓包进程失败：" + str(exc))
                new_pids = self._active_pids(current) - baseline_pids
                step["observed_new_pids"] = sorted(new_pids)
                if len(new_pids) > 1:
                    step["status"] = "ambiguous"
                    return finish(f"{link} 提示后同时出现多个新抓包进程，已停止自动绑定；请明确对应文件。")
                if len(new_pids) == 1:
                    pid = next(iter(new_pids))
                    matches = [c for c in current if c.get("pid") is not None and int(c["pid"]) == pid]
                    unique = {_path_key(c["path"]): c for c in matches}
                    if len(unique) > 1:
                        step["status"] = "ambiguous"
                        return finish(f"{link} 的新进程对应多份抓包文件，已停止自动绑定；请明确文件。")
                    if len(unique) == 1:
                        candidate = next(iter(unique.values()))
                        created = candidate.get("started_at")
                        try:
                            born_after_prompt = datetime.fromisoformat(created).astimezone(timezone.utc) >= datetime.fromisoformat(prompted_at)
                        except (TypeError, ValueError):
                            born_after_prompt = False
                        if not born_after_prompt or not candidate.get("capture_helper_pid"):
                            step["status"] = "unverified"
                            step["candidate"] = candidate
                            return finish(f"{link} 新捕获的出生时刻或 eNSP IP_Capture 父链缺失，已停止自动绑定；请明确对应文件。")
                        if stable_pid != pid:
                            stable_pid, stable_since = pid, time.monotonic()
                        if time.monotonic() - stable_since >= settle_seconds:
                            candidate = {**candidate, "link": link,
                                         "identity_basis": "用户按该链路提示启动的唯一新eNSP捕获（出生时间与父链已核对）",
                                         "enrollment_path": str(journal_path), "prompted_at": prompted_at}
                            try:
                                parsed, identity, stat = self._snapshot(candidate, require_complete=False)
                            except IncompleteCapture:
                                pass  # 新建文件头仍在写入，继续等其完整。
                            except (CaptureError, OSError) as exc:
                                step["status"] = "invalid_capture"
                                return finish(f"{link} 新抓包尚不可用：{exc}")
                            else:
                                self._archive(candidate, parsed, identity, stat)
                                # 只替换此次提示前缺失的映射；已验证活跃的链路保留。
                                if link not in self.sources:
                                    step["previous_mapping"] = self.mapping.get(link)
                                    self.mapping[link] = candidate
                                step.update(status="bound", candidate=candidate, bound_at=now())
                                write_json(journal_path, journal)
                                progress(f"已关联 {link}（dumpcap PID {pid}）。")
                                accepted = True
                                break
                else:
                    stable_pid, stable_since = None, None
                time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))
            if not accepted:
                step["status"] = "timeout"
                return finish(f"等待 {link} 新抓包超时；已关联的链路保留。")
        return finish()

    def _snapshot(self, source, *, require_complete):
        path = Path(source["path"])
        deadline = time.monotonic() + self.retry_seconds
        while True:
            try:
                before = path.stat()
                with path.open("rb") as stream:
                    # 固定读入本次 stat 时的长度；后续追加归入下一次快照。
                    data = stream.read(before.st_size)
                    fdstat = os.fstat(stream.fileno())
                after = path.stat()
                identity = (before.st_dev, before.st_ino)
                if identity != (fdstat.st_dev, fdstat.st_ino) or identity != (after.st_dev, after.st_ino):
                    raise CaptureError("读取期间抓包文件已轮换或替换，请重新明确映射并建立检查点。")
                if len(data) != before.st_size or after.st_size < len(data):
                    raise CaptureError("读取期间抓包文件被截断，请重新建立检查点。")
                parsed = parse_capture(data, allow_partial=not require_complete)
                if parsed.pending_bytes and time.monotonic() < deadline:
                    time.sleep(min(.05, max(0, deadline - time.monotonic())))
                    continue
                return parsed, identity, before
            except IncompleteCapture:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(min(.05, max(0, deadline - time.monotonic())))

    def _archive(self, source, parsed, identity, stat):
        self._prepare_output()
        digest = sha256(parsed.data)
        directory = self.output_dir / "raw"
        directory.mkdir(exist_ok=True)
        target = directory / (digest + "." + parsed.format)
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(parsed.data)
        elif sha256(target.read_bytes()) != digest:
            raise CaptureError("原始归档副本哈希不符，请保留目录核查。")
        return {"path": source["path"], "raw_copy": str(target), "sha256": digest,
                "size_bytes": len(parsed.data), "complete_end": parsed.complete_end,
                "pending_bytes": parsed.pending_bytes, "complete_frames": len(parsed.frames),
                "file_identity": list(identity), "mtime_ns": stat.st_mtime_ns,
                "capture_pid": source.get("pid"), "capture_interface": source.get("interface"),
                "identity_basis": source["identity_basis"], "snapshotted_at": now()}

    def checkpoint(self, label=None):
        if self.require_active or set(self.sources) != set(self.required_links):
            discovery = self.discover()
            if discovery["needs_input"]:
                return {**discovery, "checkpoint": None, "token": None}
        self._prepare_output()
        token, entries, missing = uuid.uuid4().hex, {}, []
        for link in self.required_links:
            source = self.sources[link]
            try:
                parsed, identity, stat = self._snapshot(source, require_complete=True)
                archive = self._archive(source, parsed, identity, stat)
                entries[link] = {**archive, "offset": parsed.complete_end, "frame": len(parsed.frames),
                                 "prefix_sha256": sha256(parsed.data[:parsed.complete_end])}
            except (CaptureError, OSError) as exc:
                missing.append({"link": link, "reason": str(exc)})
        result = {"status": "ready" if not missing else "incomplete", "token": token if not missing else None,
                  "label": label, "created_at": now(), "captures": entries, "missing": missing,
                  "checkpoint": token if not missing else None}
        write_json(self.output_dir / f"checkpoint-{token}.json", result)
        if not missing:
            self.checkpoints[token] = result
            self.last_checkpoint = token
        return result

    def export_phase(self, stage, checkpoint=None, expectations=None):
        """不自动移动起点；阶段和各次 ping 可各自保留独立 token。"""
        token = checkpoint.get("token") if isinstance(checkpoint, dict) else checkpoint
        token = token or self.last_checkpoint
        if not token or token not in self.checkpoints:
            raise CaptureError("请在本阶段或本次 ping 之前成功建立检查点。")
        baseline = self.checkpoints[token]
        self._prepare_output()
        name = re.sub(r"[^\w.-]", "_", str(stage))[:100] or "stage"
        folder = self.output_dir / (name + "-" + uuid.uuid4().hex[:12])
        folder.mkdir(exist_ok=False)
        evidence, missing = {}, []
        for link in self.required_links:
            start, source = baseline["captures"][link], self.sources[link]
            try:
                if _path_key(source["path"]) != _path_key(start["path"]):
                    raise CaptureError("检查点后源路径已改变；请保留原始副本并重新建立检查点。")
                parsed, identity, stat = self._snapshot(source, require_complete=False)
                archive = self._archive(source, parsed, identity, stat)
                if list(identity) != start["file_identity"] or parsed.complete_end < start["offset"]:
                    raise CaptureError("检查点后文件已轮换、替换或截断；本窗口拒绝混入新文件，请重建检查点。")
                if sha256(parsed.data[:start["offset"]]) != start["prefix_sha256"]:
                    raise CaptureError("检查点前的原始字节已变化（同路径复用）；本窗口拒绝导出，请重建检查点。")
                payload, selected = capture_window(parsed, start["offset"])
                safe_link = re.sub(r"[^\w.-]", "_", link)
                output = folder / (safe_link + "." + parsed.format)
                output.write_bytes(payload)
                analysis = analyze_frames(selected, self.hosts, self.kind)
                analysis_path = folder / (safe_link + "-analysis.json")
                write_json(analysis_path, analysis)
                evidence[link] = {"link": link, "source": archive, "checkpoint_source": start,
                                  "window_path": str(output), "window_sha256": sha256(payload),
                                  "start_offset": start["offset"], "end_offset": parsed.complete_end,
                                  "first_source_frame": selected[0].number if selected else None,
                                  "last_source_frame": selected[-1].number if selected else None,
                                  "frame_count": len(selected), "analysis_path": str(analysis_path),
                                  "analysis": analysis,
                                  "pcapng_metadata_note": "窗口包含原始SHB/IDB；固定section长度改为未知；包block逐字节保留"
                                  if parsed.format == "pcapng" else None}
                if parsed.pending_bytes:
                    missing.append({"link": link, "reason": "源尾部尚有半帧，窗口仅含完整帧；原始副本保留半帧，请稍后重新导出。"})
            except (CaptureError, OSError) as exc:
                missing.append({"link": link, "reason": str(exc)})
        ping_results, gaps = self._check_expectations(evidence, expectations)
        missing.extend(gaps)
        result = {"data_kind": self.kind, "segmentation": "按检查点分段的原始帧", "stage": stage, "checkpoint": token,
                  "started_at": baseline["created_at"], "exported_at": now(),
                  "capture_evidence": evidence, "missing": missing, "ping_results": ping_results,
                  "status": "complete" if not missing else "incomplete", "output_dir": str(folder),
                  "summary_path": str(folder / "capture-summary.json")}
        write_json(result["summary_path"], result)
        return result

    def _check_expectations(self, evidence, expectations):
        if not expectations:
            return [], []
        if isinstance(expectations, dict):
            expectations = [{"source": "PC1", "target": target, "reachable": value}
                            for target, value in expectations.items()]
        results, missing = [], []
        for expected in expectations:
            source_name, target_name = expected.get("source", "PC1"), expected["target"]
            source_ip = self.hosts.get(source_name, {}).get("ip", source_name)
            target_ip = self.hosts.get(target_name, {}).get("ip", target_name)
            requests, replies, pairs, arp_requests = [], [], [], []
            gateway_requests = []
            gateway = self.hosts.get(source_name, {}).get("gateway")
            for link, item in evidence.items():
                if expected.get("links") and link not in expected["links"]:
                    continue
                for row in item["analysis"]["frames"]:
                    if row.get("protocol") == "ARP" and row.get("arp_opcode") == 1 and row.get("source_ip") == source_ip:
                        evidence_row = {"link": link, "frame": row["source_frame"], "target_ip": row.get("destination_ip")}
                        if row.get("destination_ip") == target_ip:
                            arp_requests.append(evidence_row)
                        elif gateway and row.get("destination_ip") == gateway:
                            gateway_requests.append(evidence_row)
                    if row.get("icmp_code") != 0 or not row.get("icmp_complete"):
                        continue
                    if (row.get("source_ip"), row.get("destination_ip"), row.get("icmp_type")) == (source_ip, target_ip, 8):
                        requests.append({"link": link, "frame": row["source_frame"]})
                    if (row.get("source_ip"), row.get("destination_ip"), row.get("icmp_type")) == (target_ip, source_ip, 0):
                        replies.append({"link": link, "frame": row["source_frame"]})
                pairs.extend({"link": link, **pair} for pair in item["analysis"]["icmp_echo_pairs"]
                             if (pair["source_ip"], pair["destination_ip"]) == (source_ip, target_ip))
            wanted = expected.get("reachable")
            # 同网段隔离时先出现未应答的目标ARP；无需等待本来就不会发出的Echo。
            if wanted is False and not requests and arp_requests and not replies:
                status, gap = "arp_request_without_echo_reply", None
            elif (wanted is False and not requests and not replies and gateway_requests
                  and expected.get("allow_gateway_arp") is True):
                # 调用者只在单次ping窗口中开启此选项，避免把阶段内的网关ARP分配给所有目标。
                status, gap = "gateway_arp_without_echo_reply", None
            elif not requests:
                status, gap = "missing_request", "窗口内缺少指定源/目标的完整ICMP Echo请求证据"
            elif wanted is True and not pairs:
                status, gap = "missing_reply", "预期连通，但窗口内缺少匹配的Echo应答"
            elif wanted is False and replies:
                status, gap = "unexpected_reply", "预期隔离，但窗口内观察到Echo应答"
            else:
                status, gap = "matched" if pairs else "request_without_reply", None
            result = {"source": source_name, "target": target_name, "source_ip": source_ip, "target_ip": target_ip,
                      "expected_reachable": wanted, "observed_reachable": True if pairs else None,
                      "status": status, "requests": requests, "replies": replies, "pairs": pairs,
                      "arp_requests_to_target": arp_requests, "arp_requests_to_gateway": gateway_requests}
            results.append(result)
            if gap:
                missing.append({"source": source_name, "target": target_name, "reason": gap})
        return results, missing


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True,
                        help="local目录中的JSON，含required_links/hosts/output_dir及可选mapping/link_metadata")
    parser.add_argument("--stage", help="指定后等待用户自行发包，按回车导出本次窗口")
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text(encoding="utf-8-sig"))
        session = CaptureSession(**config)
        discovery = session.discover()
        if discovery["needs_input"]:
            print(json.dumps(discovery, ensure_ascii=False, indent=2))
            return 2
        if not args.stage:
            print(json.dumps(discovery, ensure_ascii=False, indent=2))
            return 0
        checkpoint = session.checkpoint(args.stage)
        if checkpoint["status"] != "ready":
            print(json.dumps(checkpoint, ensure_ascii=False, indent=2))
            return 2
        input("检查点已记录。请完成本阶段发包，完成后按回车导出：")
        result = session.export_phase(args.stage, checkpoint)
        print(json.dumps({"status": result["status"], "summary_path": result["summary_path"],
                          "missing": result["missing"]}, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "complete" else 2
    except (CaptureError, OSError, ValueError) as exc:
        print(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
