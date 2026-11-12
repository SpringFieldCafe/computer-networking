"""离线分析器测试；本文件所有PCAP均为人工构造的测试夹具，不是课程实测。"""
import csv
import io
import ipaddress
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import analyze_capture as analyzer


def fixture_row(number, **fields):
    row = dict.fromkeys(analyzer.FIELDS, "")
    row.update({"frame.number": str(number), "frame.time_relative": str(number / 10),
                "eth.src": "02:00:00:00:00:01", "eth.dst": "02:00:00:00:00:03", "eth.type": "0x0800"})
    row.update(fields)
    return row


def echo(number, source, target, reply=False, identifier="0x1234", sequence="1", **fields):
    return fixture_row(number, **{"ip.src": source, "ip.dst": target, "ip.ttl": "64",
        "icmp.type": "0" if reply else "8", "icmp.code": "0", "icmp.ident": identifier,
        "icmp.seq": sequence, **fields})


def arp(number, source, target, reply=False, **fields):
    return fixture_row(number, **{"eth.type": "0x0806", "arp.opcode": "2" if reply else "1",
        "arp.src.proto_ipv4": source, "arp.dst.proto_ipv4": target,
        "arp.src.hw_mac": "02:00:00:00:00:03" if reply else "02:00:00:00:00:01",
        "arp.dst.hw_mac": "02:00:00:00:00:01" if reply else "00:00:00:00:00:00", **fields})


class FakeTshark:
    """只模拟外部进程响应；真实git检查仍执行，测试断言ASCII临时副本。"""

    def __init__(self, rows=(), fields=None, fail=None, empty_stdout=False, rename=None):
        self.rows, self.fields = list(rows), list(fields or analyzer.FIELDS)
        self.fail, self.empty_stdout, self.rename = fail, empty_stdout, rename or {}
        self.real_run = subprocess.run
        self.calls = []

    def __call__(self, command, cwd=None, **kwargs):
        if command[0] == "git":
            return self.real_run(command, cwd=cwd, **kwargs)
        label = "version" if "-v" in command else "fields" if "-G" in command else "export"
        self.calls.append((label, command, Path(cwd)))
        if label == self.fail:
            return subprocess.CompletedProcess(command, 9, b"", b"TEST_FIXTURE: invalid capture input")
        if label == "version":
            return subprocess.CompletedProcess(command, 0, b"TShark 1.4.3 TEST MOCK\n", b"test warning")
        if label == "fields":
            stdout = "\n".join(f"F\ttest\t{self.rename.get(field, field)}\tFT_STRING\ttest\t" for field in self.fields)
        else:
            assert str(cwd).isascii(), "旧版TShark的运行目录必须为ASCII"
            assert command[command.index("-r") + 1] == "input.pcap"
            assert (Path(cwd) / "input.pcap").is_file()
            requested = [command[i + 1] for i, value in enumerate(command) if value == "-e"]
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
            writer.writerow(requested)
            reverse = {new: old for old, new in self.rename.items()}
            for row in self.rows:
                writer.writerow([row.get(reverse.get(field, field), "") for field in requested])
            stdout = "" if self.empty_stdout else buffer.getvalue()
        return subprocess.CompletedProcess(command, 0, stdout.encode(), b"")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


MAC1 = bytes.fromhex("020000000001")
MAC3 = bytes.fromhex("020000000003")
GATEWAY = bytes.fromhex("0200000000fe")


def ethernet(src, dst, ethertype, payload, vlan=None):
    if vlan is None:
        header = dst + src + struct.pack("!H", ethertype)
    else:
        header = dst + src + struct.pack("!HHH", 0x8100, vlan, ethertype)
    return (header + payload).ljust(60, b"\0")


def arp_packet(reply=False):
    src, dst = (MAC3, MAC1) if reply else (MAC1, bytes(6))
    src_ip, dst_ip = (("192.168.100.3", "192.168.100.1") if reply
                      else ("192.168.100.1", "192.168.100.3"))
    payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2 if reply else 1)
    payload += src + ipaddress.ip_address(src_ip).packed + dst + ipaddress.ip_address(dst_ip).packed
    return ethernet(src, MAC1 if reply else b"\xff" * 6, 0x0806, payload)


def icmp_packet(source, target, reply=False, vlan=None):
    payload = b"TEST_FIXTURE_NOT_A_COURSE_MEASUREMENT"
    echo_header = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, 0x1234, 1)
    echo_data = echo_header + payload
    echo_data = echo_data[:2] + struct.pack("!H", checksum(echo_data)) + echo_data[4:]
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(echo_data), 1, 0, 64, 1, 0,
                            ipaddress.ip_address(source).packed, ipaddress.ip_address(target).packed)
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    src, dst = ((MAC3, MAC1) if reply else (MAC1, MAC3))
    if vlan is not None:
        src, dst = ((GATEWAY, MAC1) if reply else (MAC1, GATEWAY))
    return ethernet(src, dst, 0x0800, ip_header + echo_data, vlan)


def write_fixture_pcap(path, frames):
    # 标准little-endian PCAP，时间戳纯属夹具中的固定数值。
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            stream.write(struct.pack("<IIII", 1000000000, index * 1000, len(frame), len(frame)))
            stream.write(frame)


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.selected = dict(zip(analyzer.FIELDS, analyzer.FIELDS))

    def summarize(self, rows, scenario="inter-vlan"):
        return analyzer.summarize(rows, self.selected, scenario, kind="测试夹具")

    def test_same_and_cross_vlan_echo_and_arp(self):
        rows = [arp(1, "192.168.100.1", "192.168.100.3"),
                arp(2, "192.168.100.3", "192.168.100.1", reply=True),
                echo(3, "192.168.100.1", "192.168.100.3"),
                echo(4, "192.168.100.3", "192.168.100.1", reply=True),
                echo(5, "192.168.100.1", "192.168.200.2", **{"vlan.id": "100"}),
                echo(6, "192.168.200.2", "192.168.100.1", reply=True, **{"vlan.id": "100", "ip.ttl": "63"})]
        summary = self.summarize(rows)
        self.assertEqual(summary["protocol_counts"]["icmp_echo_requests"], 2)
        self.assertEqual(summary["protocol_counts"]["icmp_echo_replies"], 2)
        self.assertEqual(summary["protocol_counts"]["arp_requests"], 1)
        self.assertEqual(summary["protocol_counts"]["arp_replies"], 1)
        self.assertEqual([group["vlan_relation"] for group in summary["icmp_echo_groups"]], ["same_vlan", "cross_vlan"])
        self.assertEqual(summary["observed_vlan_ids"], {"100": 2})
        self.assertEqual(len(summary["icmp_echo_pairs"]), 2)
        self.assertEqual(summary["arp_pairs"][0]["resolved_mac"], "02:00:00:00:00:03")
        self.assertEqual(summary["icmp_echo_groups"][1]["observed_ttls"], {"63": 1, "64": 1})
        self.assertEqual(summary["data_kind"], "测试夹具")

    def test_missing_ident_or_code_preserves_counts_without_pair(self):
        rows = [echo(1, "192.168.100.1", "192.168.100.3", identifier=""),
                echo(2, "192.168.100.3", "192.168.100.1", reply=True, identifier=""),
                echo(3, "192.168.100.1", "192.168.100.3", **{"icmp.code": ""})]
        summary = self.summarize(rows)
        self.assertEqual(summary["icmp_echo_pairs"], [])
        self.assertEqual(summary["protocol_counts"]["icmp_echo_requests"], 2)
        self.assertEqual(summary["field_evidence"]["icmp"]["blank_values"]["icmp.ident"], 2)
        self.assertTrue(any("code" in gap for gap in summary["evidence_gaps"]))

    def test_reply_before_request_and_duplicate_sequence(self):
        rows = [echo(1, "192.168.100.3", "192.168.100.1", reply=True),
                echo(2, "192.168.100.1", "192.168.100.3"),
                echo(3, "192.168.100.1", "192.168.100.3"),
                echo(4, "192.168.100.3", "192.168.100.1", reply=True)]
        summary = self.summarize(rows)
        self.assertEqual(summary["icmp_echo_pairs"][0]["request_frame"], "2")
        self.assertEqual(len(summary["icmp_echo_pairs"]), 1)
        self.assertEqual(summary["icmp_echo_groups"][0]["unpaired_request_frames"], 1)
        self.assertEqual(summary["icmp_echo_groups"][0]["unpaired_reply_frames"], 1)

    def test_unknown_addresses_port_vlan_and_nested_tags(self):
        for scenario in ["auto", "port-vlan", "inter-vlan"]:
            with self.subTest(scenario=scenario):
                row = echo(1, "192.0.2.1", "192.0.2.2", **{"vlan.id": "1,2"})
                summary = self.summarize([row], scenario)
                self.assertEqual(summary["icmp_echo_groups"][0]["vlan_relation"], "unknown")
                self.assertEqual(summary["observed_vlan_ids"], {"1": 1, "2": 1})
        summary = self.summarize([echo(1, "192.168.100.1", "192.168.200.2")], "port-vlan")
        self.assertEqual(summary["icmp_echo_groups"][0]["vlan_relation"], "unknown")

    def test_other_protocols_and_arp_hardware_mismatch(self):
        rows = [fixture_row(1, **{"icmp.type": "3"}), fixture_row(2, **{"arp.opcode": "3"}),
                arp(3, "192.168.100.1", "192.168.100.3"),
                arp(4, "192.168.100.3", "192.168.100.1", reply=True,
                    **{"arp.dst.hw_mac": "02:00:00:00:00:99"})]
        summary = self.summarize(rows)
        self.assertEqual(summary["protocol_counts"]["other_icmp"], 1)
        self.assertEqual(summary["protocol_counts"]["other_arp"], 1)
        self.assertEqual(summary["arp_pairs"], [])

    def test_no_addresses_do_not_match(self):
        rows = [echo(1, "", ""), echo(2, "", "", reply=True),
                arp(3, "", ""), arp(4, "", "", reply=True)]
        summary = self.summarize(rows)
        self.assertEqual(summary["icmp_echo_pairs"], [])
        self.assertEqual(summary["arp_pairs"], [])

    def test_malformed_csv_is_diagnostic(self):
        with self.assertRaisesRegex(analyzer.AnalysisError, "表头"):
            analyzer.parse_export(b'"frame.number"\n"1"\n', self.selected)
        selected = {field: field if field == "frame.number" else None for field in analyzer.FIELDS}
        with self.assertRaisesRegex(analyzer.AnalysisError, "列数"):
            analyzer.parse_export(b'"frame.number"\n"1","extra"\n', selected)
        with self.assertRaisesRegex(analyzer.AnalysisError, "frame.number"):
            analyzer.parse_export(b'"frame.number"\n"bad"\n', selected)


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        analyzer.ANALYSIS_ROOT.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.fixture_temp = tempfile.TemporaryDirectory(prefix="测试夹具-非实测-", dir=analyzer.ANALYSIS_ROOT)
        self.addCleanup(self.fixture_temp.cleanup)
        self.fixture_root = Path(self.fixture_temp.name)
        self.capture = self.fixture_root / "人工构造的空抓包.pcap"
        write_fixture_pcap(self.capture, [])
        self.binary = self.fixture_root / "mock-tshark.exe"
        self.binary.write_bytes(b"TEST_FIXTURE_MOCK_ONLY")

    def analyze(self, fake=None):
        with mock.patch.object(analyzer.subprocess, "run", side_effect=fake or FakeTshark()):
            return analyzer.analyze(self.capture, self.binary, kind="测试夹具")

    def test_chinese_input_ascii_copy_and_reproducible_metadata(self):
        before = analyzer.digest(self.capture)
        output, summary = self.analyze(FakeTshark([echo(1, "192.168.100.1", "192.168.200.2")]))
        record = json.loads((output / "运行记录.json").read_text(encoding="utf-8"))
        self.assertEqual(record["source"]["sha256"], before)
        self.assertEqual(record["parsed_input_sha256"], before)
        self.assertEqual(analyzer.digest(self.capture), before)
        self.assertTrue(record["started_at"].endswith("+08:00"))
        self.assertTrue(record["finished_at"].endswith("+08:00"))
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["tshark_version"], "TShark 1.4.3 TEST MOCK")
        self.assertEqual([command["name"] for command in record["commands"]], ["version", "fields", "export"])
        self.assertEqual((output / "version-stderr.txt").read_bytes(), b"test warning")
        self.assertEqual(summary["total_frames"], 1)
        self.assertIn("测试夹具", (output / "汇总.md").read_text(encoding="utf-8"))
        self.assertEqual(output.parent, analyzer.ANALYSIS_ROOT)
        self.assertTrue(output.name.endswith("+0800"))

    def test_empty_capture_with_header_and_legacy_no_header(self):
        for empty_stdout in [False, True]:
            with self.subTest(empty_stdout=empty_stdout):
                output, summary = self.analyze(FakeTshark(empty_stdout=empty_stdout))
                self.assertEqual(summary["total_frames"], 0)
                self.assertTrue(any("0帧" in gap for gap in summary["evidence_gaps"]))
                self.assertTrue((output / "字段.csv").is_file())

    def test_missing_fields_export_stable_columns_and_gaps(self):
        available = [field for field in analyzer.FIELDS if field not in ("icmp.ident", "vlan.id", "arp.src.hw_mac")]
        output, summary = self.analyze(FakeTshark([echo(1, "192.168.100.1", "192.168.100.3")], fields=available))
        self.assertEqual(set(summary["missing_fields"]), {"icmp.ident", "vlan.id", "arp.src.hw_mac"})
        with (output / "字段.csv").open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(rows[0]["icmp.ident"], "")
        self.assertEqual(summary["icmp_echo_pairs"], [])

    def test_detect_alternative_field_name(self):
        _, summary = self.analyze(FakeTshark([echo(1, "192.168.100.1", "192.168.100.3")],
                                           rename={"icmp.ident": "icmp.id", "icmp.seq": "icmp.sequence_number"}))
        self.assertEqual(summary["selected_fields"]["icmp.ident"], "icmp.id")
        self.assertEqual(summary["missing_fields"], [])

    def test_failure_records_stderr_and_does_not_overwrite(self):
        earlier, _ = self.analyze()
        earlier_record = (earlier / "运行记录.json").read_bytes()
        before = set(analyzer.ANALYSIS_ROOT.iterdir())
        with self.assertRaisesRegex(analyzer.AnalysisError, "export-stderr.txt"):
            self.analyze(FakeTshark(fail="export"))
        added = set(analyzer.ANALYSIS_ROOT.iterdir()) - before
        self.assertEqual(len(added), 1)
        output = added.pop()
        record = json.loads((output / "运行记录.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["commands"][-1]["returncode"], 9)
        self.assertIn(b"invalid capture", (output / "export-stderr.txt").read_bytes())
        self.assertEqual((earlier / "运行记录.json").read_bytes(), earlier_record)
        self.assertFalse((output / "汇总.json").exists())

    def test_missing_tool_records_failure(self):
        before = set(analyzer.ANALYSIS_ROOT.iterdir())
        with self.assertRaisesRegex(analyzer.AnalysisError, "找不到 TShark"):
            analyzer.analyze(self.capture, self.fixture_root / "missing.exe", kind="测试夹具")
        output = (set(analyzer.ANALYSIS_ROOT.iterdir()) - before).pop()
        self.assertEqual(json.loads((output / "运行记录.json").read_text(encoding="utf-8"))["status"], "failed")

    def test_probe_missing_frame_number_fails_before_export(self):
        fake = FakeTshark(fields=["eth.src", "ip.src"])
        with self.assertRaisesRegex(analyzer.AnalysisError, "frame.number"):
            self.analyze(fake)
        self.assertEqual([call[0] for call in fake.calls], ["version", "fields"])

    def test_timeout_preserves_partial_output(self):
        fake = FakeTshark()

        def timed(command, **kwargs):
            if "-r" in command:
                raise subprocess.TimeoutExpired(command, 0.01, output=b"partial", stderr=b"TEST_TIMEOUT")
            return fake(command, **kwargs)

        before = set(analyzer.ANALYSIS_ROOT.iterdir())
        with mock.patch.object(analyzer.subprocess, "run", side_effect=timed):
            with self.assertRaisesRegex(analyzer.AnalysisError, "超过"):
                analyzer.analyze(self.capture, self.binary, timeout=0.01, kind="测试夹具")
        output = (set(analyzer.ANALYSIS_ROOT.iterdir()) - before).pop()
        self.assertEqual((output / "export-stdout.txt").read_bytes(), b"partial")
        self.assertEqual((output / "export-stderr.txt").read_bytes(), b"TEST_TIMEOUT")

    def test_non_ignored_output_is_refused(self):
        with mock.patch.object(analyzer.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"")):
            with self.assertRaisesRegex(analyzer.AnalysisError, "未被 Git 忽略"):
                analyzer.create_run_directory()

    def test_real_tshark_fixture_if_installed(self):
        try:
            binary = analyzer.resolve_tshark()
        except analyzer.AnalysisError:
            self.skipTest("本机无TShark；已有mock覆盖，真实集成测试跳过")
        frames = [arp_packet(), arp_packet(True),
                  icmp_packet("192.168.100.1", "192.168.100.3"),
                  icmp_packet("192.168.100.3", "192.168.100.1", reply=True),
                  icmp_packet("192.168.100.1", "192.168.200.2", vlan=100),
                  icmp_packet("192.168.200.2", "192.168.100.1", reply=True, vlan=100)]
        capture = self.fixture_root / "人工构造-ICMP-ARP-VLAN-非实测.pcap"
        write_fixture_pcap(capture, frames)
        _, summary = analyzer.analyze(capture, binary, kind="测试夹具")
        self.assertEqual(summary["total_frames"], 6)
        self.assertEqual(summary["protocol_counts"]["arp_requests"], 1)
        self.assertEqual(summary["protocol_counts"]["arp_replies"], 1)
        self.assertEqual(summary["protocol_counts"]["icmp_echo_requests"], 2)
        self.assertEqual(summary["protocol_counts"]["icmp_echo_replies"], 2)
        self.assertEqual(summary["observed_vlan_ids"], {"100": 2})
        self.assertEqual(len(summary["icmp_echo_pairs"]), 2)
        self.assertEqual(len(summary["arp_pairs"]), 1)
        # 同时验证本机TShark对真正零帧PCAP的表现。
        _, empty_summary = analyzer.analyze(self.capture, binary, kind="测试夹具")
        self.assertEqual(empty_summary["total_frames"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
