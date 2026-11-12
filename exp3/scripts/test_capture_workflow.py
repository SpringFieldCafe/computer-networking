"""构造 PCAP/PCAPNG 的测试夹具；不连接设备、不启动抓包，不作为实验实测。"""
import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import capture_workflow as capture


HOSTS = {"PC1": {"ip": "192.0.2.1", "mac": "02-00-00-00-00-01"},
         "PC2": {"ip": "192.0.2.2", "mac": "02-00-00-00-00-02"}}
MAC1 = bytes.fromhex("020000000001")
MAC2 = bytes.fromhex("020000000002")


def ethernet_echo(reply=False, vlan=None, sequence=1, payload=b"fixture", code=0):
    src, dst = ("192.0.2.2", "192.0.2.1") if reply else ("192.0.2.1", "192.0.2.2")
    smac, dmac = (MAC2, MAC1) if reply else (MAC1, MAC2)
    icmp = struct.pack("!BBHHH", 0 if reply else 8, code, 0, 0x1234, sequence) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 7, 0, 64, 1, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    eth = dmac + smac
    eth += struct.pack("!HHH", 0x8100, vlan, 0x800) if vlan is not None else struct.pack("!H", 0x800)
    return eth + ip + icmp


def ethernet_arp(reply=False):
    smac, dmac = (MAC2, MAC1) if reply else (MAC1, b"\xff" * 6)
    sip, dip = ("192.0.2.2", "192.0.2.1") if reply else ("192.0.2.1", "192.0.2.2")
    target = MAC1 if reply else b"\0" * 6
    return dmac + smac + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x800, 6, 4, 2 if reply else 1) + smac + ipaddress.IPv4Address(sip).packed + target + ipaddress.IPv4Address(dip).packed


def pcap_header(endian="<", nano=False, linktype=1):
    return struct.pack(endian + "IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)


def record(packet, sec=1700000000, sub=123456, endian="<"):
    return struct.pack(endian + "IIII", sec, sub, len(packet), len(packet)) + packet


def block(kind, body, endian="<"):
    body += b"\0" * ((-len(body)) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def ng_header(endian="<", resolution=9, fixed_length=False):
    shb = block(0x0a0d0d0a, struct.pack(endian + "IHHq", 0x1a2b3c4d, 1, 0, 1234 if fixed_length else -1), endian)
    options = struct.pack(endian + "HHB", 9, 1, resolution) + b"\0" * 3 + struct.pack(endian + "HH", 0, 0)
    idb = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + options, endian)
    return shb + idb


def ng_packet(packet, ticks=1700000000123456789, endian="<", interface=0):
    return block(6, struct.pack(endian + "IIIII", interface, ticks >> 32, ticks & 0xffffffff, len(packet), len(packet)) + packet, endian)


class ParsingTests(unittest.TestCase):
    def test_all_pcap_endian_and_timestamp_resolutions(self):
        packet = ethernet_echo()
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    raw = pcap_header(endian, nano) + record(packet, endian=endian)
                    parsed = capture.parse_capture(raw)
                    frame = parsed.frames[0]
                    self.assertEqual(frame.packet, packet)
                    self.assertEqual(frame.timestamp_scale, 10**9 if nano else 10**6)
                    self.assertEqual(frame.timestamp_ticks % frame.timestamp_scale, 123456)
                    self.assertEqual(capture.capture_window(parsed, 24)[0], raw)

    def test_pcap_partial_record_does_not_escape_window(self):
        one = record(ethernet_echo())
        raw = pcap_header() + one + one[:19]
        with self.assertRaises(capture.IncompleteCapture):
            capture.parse_capture(raw)
        parsed = capture.parse_capture(raw, allow_partial=True)
        self.assertEqual(parsed.pending_bytes, 19)
        window, frames = capture.capture_window(parsed, 24)
        self.assertEqual(window, pcap_header() + one)
        self.assertEqual(len(frames), 1)

    def test_pcapng_original_packet_blocks_and_timestamp(self):
        for endian in ("<", ">"):
            with self.subTest(endian=endian):
                header = ng_header(endian)
                old, new = ng_packet(ethernet_echo(), endian=endian), ng_packet(ethernet_echo(True), endian=endian)
                parsed = capture.parse_capture(header + old + new)
                payload, selected = capture.capture_window(parsed, len(header + old))
                self.assertEqual(payload, header + new)
                self.assertEqual(selected[0].number, 2)
                self.assertEqual(selected[0].timestamp_ticks, 1700000000123456789)
                self.assertEqual(selected[0].timestamp_scale, 10**9)
                self.assertEqual(capture.parse_capture(payload).frames[0].packet, ethernet_echo(True))

    def test_pcapng_multiple_sections_and_fixed_section_length(self):
        raw = ng_header(fixed_length=True) + ng_packet(ethernet_echo())
        boundary = len(raw)
        raw += ng_header(">", resolution=0x80 | 10) + ng_packet(ethernet_echo(True), endian=">")
        parsed = capture.parse_capture(raw)
        window, selected = capture.capture_window(parsed, boundary)
        decoded = capture.parse_capture(window)
        self.assertEqual(len(decoded.frames), 1)
        self.assertEqual(decoded.frames[0].timestamp_scale, 2**10)
        full, _ = capture.capture_window(parsed, 0)
        self.assertEqual(struct.unpack_from("<q", full, 16)[0], -1)
        self.assertEqual(selected[0].number, 2)

    def test_empty_pcapng_window_is_readable(self):
        raw = ng_header() + ng_packet(ethernet_echo())
        parsed = capture.parse_capture(raw)
        window, frames = capture.capture_window(parsed, len(raw))
        self.assertEqual(frames, [])
        self.assertEqual(capture.parse_capture(window).frames, [])

    def test_pcapng_partial_block_retry_compatible(self):
        raw = ng_header() + ng_packet(ethernet_echo())[:-1]
        with self.assertRaises(capture.IncompleteCapture):
            capture.parse_capture(raw)
        parsed = capture.parse_capture(raw, allow_partial=True)
        self.assertEqual(parsed.frames, [])
        self.assertGreater(parsed.pending_bytes, 0)

    def test_ng_unknown_interface_and_corrupt_block_rejected(self):
        with self.assertRaises(capture.CaptureError):
            capture.parse_capture(ng_header() + ng_packet(ethernet_echo(), interface=1))
        corrupt = bytearray(ng_header())
        corrupt[-1] = 8
        with self.assertRaises(capture.CaptureError):
            capture.parse_capture(bytes(corrupt))

    def test_packet_evidence_pairs_arp_vlan_icmp_and_host_identity(self):
        packets = [ethernet_arp(), ethernet_arp(True), ethernet_echo(vlan=100), ethernet_echo(True, vlan=100)]
        parsed = capture.parse_capture(pcap_header() + b"".join(record(p) for p in packets))
        analysis = capture.analyze_frames(parsed.frames, HOSTS)
        self.assertEqual(analysis["vlan_ids"], [100])
        self.assertEqual(len(analysis["arp_pairs"]), 1)
        self.assertEqual(len(analysis["icmp_echo_pairs"]), 1)
        self.assertEqual(analysis["frames"][2]["source_mac_host"], "PC1")
        self.assertEqual(analysis["icmp_echo_pairs"][0]["reply_frame"], 4)

    def test_icmp_matching_requires_reverse_address_code_and_same_payload(self):
        packets = [ethernet_echo(), ethernet_echo(True, payload=b"different"), ethernet_echo(True, code=1)]
        analysis = capture.analyze_frames(capture.parse_capture(pcap_header() + b"".join(record(p) for p in packets)).frames)
        self.assertEqual(analysis["icmp_echo_pairs"], [])
        self.assertEqual(analysis["unmatched_echo_requests"], [1])

    def test_truncated_or_fragmented_echo_not_paired(self):
        request = bytearray(ethernet_echo())
        request[20:22] = struct.pack("!H", 0x2000)  # IP MF flag
        analysis = capture.analyze_frames(capture.parse_capture(pcap_header() + record(bytes(request)) + record(ethernet_echo(True))).frames)
        self.assertEqual(analysis["icmp_echo_pairs"], [])


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        local = capture.ROOT / "exp3" / "local"
        local.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="capture-test-fixture-", dir=local)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.path = self.folder / "input.pcap"
        self.path.write_bytes(pcap_header())

    def session(self, **kwargs):
        return capture.CaptureSession(["S1-PC1"], HOSTS, self.folder / "evidence",
                                      mapping={"S1-PC1": str(self.path)}, candidates=[], retry_seconds=0,
                                      kind="测试夹具", **kwargs)

    def append(self, packet):
        with self.path.open("ab") as stream:
            stream.write(record(packet))

    def test_manual_mapping_checkpoint_phase_and_ping_keep_independent_anchors(self):
        self.append(ethernet_echo(sequence=99))
        session = self.session()
        self.assertEqual(session.discover()["status"], "ready")
        phase = session.checkpoint("phase")
        self.append(ethernet_echo(sequence=1))
        ping = session.checkpoint("ping")
        self.append(ethernet_echo(sequence=2))
        self.append(ethernet_echo(True, sequence=2))
        ping_result = session.export_phase("one-ping", ping, {"PC2": True})
        phase_result = session.export_phase("whole-phase", phase, {"PC2": True})
        self.assertEqual(ping_result["status"], "complete")
        self.assertEqual(ping_result["capture_evidence"]["S1-PC1"]["frame_count"], 2)
        self.assertEqual(phase_result["capture_evidence"]["S1-PC1"]["frame_count"], 3)
        self.assertEqual(session.last_checkpoint, ping["token"])
        item = ping_result["capture_evidence"]["S1-PC1"]
        self.assertEqual(item["first_source_frame"], 3)
        self.assertEqual(item["last_source_frame"], 4)
        self.assertEqual(Path(item["source"]["raw_copy"]).read_bytes(), self.path.read_bytes())
        self.assertEqual(item["source"]["sha256"], capture.sha256(self.path.read_bytes()))
        self.assertEqual(item["window_sha256"], capture.sha256(Path(item["window_path"]).read_bytes()))

    def test_same_path_reused_with_same_header_rejected_and_raw_saved(self):
        self.append(ethernet_echo(sequence=99))
        session = self.session()
        cp = session.checkpoint()
        self.path.write_bytes(pcap_header() + record(ethernet_echo(sequence=1)) + record(ethernet_echo(True)))
        result = session.export_phase("reuse", cp)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["capture_evidence"], {})
        self.assertIn("同路径复用", result["missing"][0]["reason"])
        self.assertGreaterEqual(len(list((self.folder / "evidence" / "raw").iterdir())), 2)

    def test_truncated_file_rejected_and_next_checkpoint_recovers(self):
        self.append(ethernet_echo())
        session = self.session()
        cp = session.checkpoint()
        self.path.write_bytes(pcap_header())
        self.assertEqual(session.export_phase("truncated", cp)["status"], "incomplete")
        next_cp = session.checkpoint()
        self.append(ethernet_echo())
        self.assertEqual(session.export_phase("after-new-checkpoint", next_cp)["status"], "complete")

    def test_replaced_file_inode_rejected_even_with_identical_prefix(self):
        session = self.session()
        cp = session.checkpoint()
        replacement = self.folder / "replacement.pcap"
        replacement.write_bytes(pcap_header() + record(ethernet_echo()))
        replacement.replace(self.path)
        result = session.export_phase("rotation", cp)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("轮换", result["missing"][0]["reason"])

    def test_tail_partial_export_preserves_full_raw_but_marks_missing(self):
        session = self.session()
        cp = session.checkpoint()
        data = record(ethernet_echo())
        self.path.write_bytes(pcap_header() + data + data[:20])
        result = session.export_phase("partial", cp)
        item = result["capture_evidence"]["S1-PC1"]
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(item["frame_count"], 1)
        self.assertEqual(item["source"]["pending_bytes"], 20)
        self.assertEqual(Path(item["source"]["raw_copy"]).read_bytes(), self.path.read_bytes())

    def test_checkpoint_half_frame_waits_then_complete_frame_is_excluded(self):
        data = record(ethernet_echo(sequence=99))
        self.path.write_bytes(pcap_header() + data[:20])
        session = self.session()
        session.retry_seconds = 1
        def finish():
            time.sleep(.07)
            with self.path.open("ab") as stream:
                stream.write(data[20:])
        writer = threading.Thread(target=finish)
        writer.start()
        try:
            cp = session.checkpoint()
        finally:
            writer.join()
        self.assertEqual(cp["status"], "ready")
        self.append(ethernet_echo(sequence=1))
        result = session.export_phase("after-half-frame", cp)
        self.assertEqual(result["capture_evidence"]["S1-PC1"]["frame_count"], 1)
        self.assertEqual(result["capture_evidence"]["S1-PC1"]["first_source_frame"], 2)

    def test_checkpoint_timeout_does_not_create_usable_token(self):
        self.path.write_bytes(pcap_header() + record(ethernet_echo())[:18])
        session = self.session()
        cp = session.checkpoint()
        self.assertEqual(cp["status"], "incomplete")
        self.assertIsNone(cp["token"])
        with self.assertRaises(capture.CaptureError):
            session.export_phase("no-baseline")

    def test_requests_without_replies_are_observation_not_claimed_unreachable(self):
        session = self.session()
        cp = session.checkpoint()
        self.append(ethernet_echo())
        result = session.export_phase("isolated", cp, {"PC2": False})
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(result["ping_results"][0]["observed_reachable"])
        self.assertEqual(result["ping_results"][0]["status"], "request_without_reply")
        expected_success = session.export_phase("expected-success", cp, {"PC2": True})
        self.assertEqual(expected_success["status"], "incomplete")

    def test_new_stage_never_uses_old_echo_reply(self):
        session = self.session()
        self.append(ethernet_echo())
        self.append(ethernet_echo(True))
        cp = session.checkpoint()
        self.append(ethernet_echo())
        result = session.export_phase("new-stage", cp, {"PC2": True})
        self.assertEqual(result["ping_results"][0]["pairs"], [])
        self.assertEqual(result["status"], "incomplete")

    def test_isolation_arp_observation_and_fixture_kind(self):
        session = self.session()
        cp = session.checkpoint()
        self.append(ethernet_arp())
        result = session.export_phase("isolated-arp", cp, {"PC2": False})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["data_kind"], "测试夹具")
        self.assertEqual(result["ping_results"][0]["status"], "arp_request_without_echo_reply")
        self.assertIsNone(result["ping_results"][0]["observed_reachable"])

    def test_ng_session_window_and_source_frame_mapping(self):
        self.path.write_bytes(ng_header() + ng_packet(ethernet_echo(sequence=99)))
        session = self.session()
        cp = session.checkpoint()
        with self.path.open("ab") as stream:
            stream.write(ng_packet(ethernet_echo()))
            stream.write(ng_packet(ethernet_echo(True)))
        result = session.export_phase("ng", cp, {"PC2": True})
        self.assertEqual(result["status"], "complete")
        item = result["capture_evidence"]["S1-PC1"]
        self.assertEqual(item["first_source_frame"], 2)
        self.assertEqual(len(capture.parse_capture(Path(item["window_path"]).read_bytes()).frames), 2)

    def test_public_or_outside_output_rejected(self):
        for folder in (capture.ROOT / "exp3" / "public-evidence", Path(tempfile.gettempdir()) / "outside-local"):
            with self.subTest(folder=folder):
                session = self.session()
                session.output_dir = folder
                with self.assertRaises(capture.CaptureError):
                    session.checkpoint()

    def test_enrollment_binds_only_unique_capture_started_for_each_prompt(self):
        old = self.folder / "other-project.pcap"
        old.write_bytes(pcap_header())
        path2 = self.folder / "pc2.pcap"
        path2.write_bytes(pcap_header())
        old_candidate = {"path": str(old), "pid": 10, "started_at": "2000-01-01T00:00:00+00:00"}
        current = [old_candidate]
        events = []
        def progress(message):
            events.append(message)
            if message.startswith("现在请"):
                link = "S1-PC1" if "S1-PC1" in message else "S1-PC2"
                current.append({"path": str(self.path if link == "S1-PC1" else path2),
                                "pid": 20 if link == "S1-PC1" else 30,
                                "started_at": capture.now(), "capture_helper_pid": 123})
        session = capture.CaptureSession(["S1-PC1", "S1-PC2"], HOSTS, self.folder / "enrollment",
                                         candidates=lambda: list(current), kind="测试夹具", retry_seconds=0)
        result = session.enroll_missing(timeout=1, progress=progress, settle_seconds=0)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(session.mapping["S1-PC1"]["pid"], 20)
        self.assertEqual(session.mapping["S1-PC2"]["pid"], 30)
        self.assertIn("唯一新eNSP", result["captures"][0]["identity_basis"])
        self.assertTrue(Path(result["enrollment_path"]).is_file())
        self.assertEqual(len([text for text in events if text.startswith("现在请")]), 2)
        self.assertNotIn(str(old), [c["path"] for c in result["captures"]])

    def test_enrollment_concurrent_captures_stop_without_guessing(self):
        second = self.folder / "second.pcap"
        second.write_bytes(pcap_header())
        current = []
        def progress(message):
            if message.startswith("现在请"):
                current.extend({"path": str(path), "pid": pid, "started_at": capture.now(),
                                "capture_helper_pid": 100} for path, pid in [(self.path, 20), (second, 30)])
        session = capture.CaptureSession(["S1-PC1"], HOSTS, self.folder / "enrollment",
                                         candidates=lambda: list(current), kind="测试夹具")
        result = session.enroll_missing(timeout=1, progress=progress, settle_seconds=0)
        self.assertEqual(result["status"], "needs_input")
        self.assertIn("多个新抓包", result["enrollment_reason"])
        self.assertFalse(session.mapping)

    def test_enrollment_rejects_old_birth_time_or_missing_ensp_ancestry(self):
        for bad in ("old-time", "missing-helper"):
            with self.subTest(bad=bad):
                current = []
                def progress(message):
                    if message.startswith("现在请"):
                        current.append({"path": str(self.path), "pid": 20,
                                        "started_at": "2000-01-01T00:00:00+00:00" if bad == "old-time" else capture.now(),
                                        "capture_helper_pid": 123 if bad == "old-time" else None})
                session = capture.CaptureSession(["S1-PC1"], HOSTS, self.folder / bad,
                                                 candidates=lambda: list(current), kind="测试夹具")
                result = session.enroll_missing(timeout=1, progress=progress, settle_seconds=0)
                self.assertEqual(result["status"], "needs_input")
                self.assertFalse(session.mapping)

    def test_enrollment_keeps_existing_mapping_and_times_out_without_input(self):
        path2 = self.folder / "missing.pcap"
        session = capture.CaptureSession(["S1-PC1", "S1-PC2"], HOSTS, self.folder / "enrollment",
                                         mapping={"S1-PC1": str(self.path)}, candidates=[], kind="测试夹具")
        events = []
        result = session.enroll_missing(timeout=.02, progress=events.append, poll_interval=.01)
        self.assertEqual(result["status"], "needs_input")
        self.assertEqual(session.mapping["S1-PC1"], str(self.path))
        self.assertEqual(len([text for text in events if text.startswith("现在请")]), 1)
        self.assertIn("S1-PC2", events[0])

    def test_stale_enrolled_mapping_not_reused_for_another_capture(self):
        session = self.session()
        session.mapping["S1-PC1"] = {"path": str(self.path), "pid": 123, "started_at": "old-time",
                                    "enrollment_path": "fixture-enrollment.json"}
        self.assertEqual(session.discover()["status"], "needs_input")

    def test_active_required_rejects_stopped_path_and_mismatched_pid(self):
        session = self.session(require_active=True)
        self.assertEqual(session.discover()["status"], "needs_input")
        session.candidates = [{"path": str(self.path), "pid": 123}]
        self.assertEqual(session.discover()["status"], "ready")
        self.assertEqual(session.sources["S1-PC1"]["pid"], 123)
        session.mapping["S1-PC1"] = {"path": str(self.path), "pid": 456}
        self.assertEqual(session.discover()["status"], "needs_input")

    def test_active_required_rechecks_process_at_every_checkpoint(self):
        session = self.session(require_active=True)
        session.candidates = [{"path": str(self.path), "pid": 123}]
        self.assertEqual(session.discover()["status"], "ready")
        session.candidates = []
        cp = session.checkpoint()
        self.assertEqual(cp["status"], "needs_input")
        self.assertIsNone(cp["token"])

    def test_enrollment_replaces_stale_mapping_only_after_unique_prompted_start(self):
        session = self.session(require_active=True)
        session.mapping["S1-PC1"] = {"path": str(self.path), "pid": 10}
        current = []
        session.candidates = lambda: list(current)
        def progress(message):
            if message.startswith("现在请"):
                current.append({"path": str(self.path), "pid": 20, "started_at": capture.now(), "capture_helper_pid": 123})
        result = session.enroll_missing(timeout=1, progress=progress, settle_seconds=0)
        self.assertEqual(result["status"], "ready")
        self.assertEqual(session.mapping["S1-PC1"]["pid"], 20)


class DiscoveryTests(unittest.TestCase):
    @staticmethod
    def ancestor_fixture():
        def process(pid, parent, name, second):
            return {"ProcessId": pid, "ParentProcessId": parent, "Name": name,
                    "started_at": f"2026-11-12T12:00:{second:02d}+00:00"}
        metadata = [process(123, 110, "dumpcap.exe", 7), process(110, 90, "Wireshark.exe", 6),
                    process(90, 80, "cmd.exe", 5), process(80, 70, "IP_Capture.exe", 4),
                    process(70, 60, "cmd.exe", 3), process(60, 50, "eNSP_Client.exe", 2),
                    process(50, 0, "explorer.exe", 1), process(999, 0, "unrelated.exe", 0)]
        details = [{**p, "CommandLine": "wireshark.exe -k -i -" if p["Name"] == "Wireshark.exe"
                    else p["Name"]} for p in metadata if p["Name"].lower() in capture.CAPTURE_PROCESS_NAMES]
        return metadata, details

    def test_process_projection_keeps_cmd_ancestors_without_command_lines(self):
        metadata, details = self.ancestor_fixture()
        # 即使测试传入的表意外带有此字段，投影也只复制允许的元数据字段。
        for process in metadata:
            if process["Name"] == "cmd.exe":
                process["CommandLine"] = "TEST_FIXTURE_PRIVATE_ANCESTOR_COMMAND"
        result = capture.capture_process_ancestors(metadata, details)
        self.assertEqual({p["ProcessId"] for p in result}, {50, 60, 70, 80, 90, 110, 123})
        for process in result:
            if process["Name"].lower() not in capture.CAPTURE_PROCESS_NAMES:
                self.assertNotIn("CommandLine", process)
        self.assertNotIn("PRIVATE_ANCESTOR", json.dumps(result))

    def test_cmd_intermediate_ancestor_reaches_ip_capture_without_reading_cmd_command(self):
        class MetadataOnly(dict):
            def get(self, key, default=None):
                if key in ("CommandLine", "command_line"):
                    raise AssertionError("ancestor command line must not be read")
                return super().get(key, default)
        metadata, details = self.ancestor_fixture()
        projected = capture.capture_process_ancestors(metadata, details)
        projected = [MetadataOnly(p) if p["Name"] == "cmd.exe" else p for p in projected]
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "wireshark_fixturea123").write_bytes(pcap_header())
            candidates = capture.discover_candidates(projected, directory)
        self.assertEqual(candidates[0]["capture_helper_pid"], 80)
        self.assertEqual(candidates[0]["interface"], "-")
        self.assertEqual([p["name"] for p in candidates[0]["capture_ancestry"]],
                         ["Wireshark.exe", "cmd.exe", "IP_Capture.exe"])
        self.assertNotIn("CommandLine", json.dumps(candidates))

    def test_missing_intermediate_ancestor_does_not_assume_available_helper_is_parent(self):
        metadata, details = self.ancestor_fixture()
        metadata = [p for p in metadata if p["ProcessId"] != 90]
        projected = capture.capture_process_ancestors(metadata, details)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "wireshark_fixturea123").write_bytes(pcap_header())
            candidates = capture.discover_candidates(projected, directory)
        self.assertIsNone(candidates[0]["capture_helper_pid"])
        self.assertEqual([p["name"] for p in candidates[0]["capture_ancestry"]], ["Wireshark.exe"])

    def test_reused_parent_pid_and_reused_capture_pid_are_rejected(self):
        metadata, details = self.ancestor_fixture()
        for process in metadata:
            if process["ProcessId"] == 90:
                process["started_at"] = "2026-11-12T13:00:00+00:00"
        details[0]["started_at"] = "2026-11-12T11:00:00+00:00"
        projected = capture.capture_process_ancestors(metadata, details)
        by_pid = {p["ProcessId"]: p for p in projected}
        self.assertNotIn(90, by_pid)
        self.assertNotIn("CommandLine", by_pid[123])

    def test_cim_queries_never_request_unrestricted_process_command_lines(self):
        metadata, details = self.ancestor_fixture()
        payload = json.dumps({"processes": metadata, "capture_details": details}).encode()
        def run(command, **kwargs):
            script = command[-1]
            metadata_query = script.split("$captureMetadata=@(", 1)[1].split("$captureDetails=@(", 1)[0]
            self.assertIn("-Property ProcessId,ParentProcessId,Name,CreationDate", metadata_query)
            self.assertNotIn("CommandLine", metadata_query)
            detail_query = script.split("$captureDetails=@(", 1)[1]
            self.assertIn("-Filter", detail_query)
            for name in ("dumpcap.exe", "Wireshark.exe", "IP_Capture.exe"):
                self.assertIn("Name='" + name + "'", detail_query)
            self.assertNotIn("Name='cmd.exe'", detail_query)
            self.assertNotIn("Name='eNSP_Client.exe'", detail_query)
            return subprocess.CompletedProcess(command, 0, payload, b"")
        with mock.patch.object(capture.os, "name", "nt"), mock.patch.object(capture.subprocess, "run", side_effect=run):
            result = capture.running_capture_processes()
        self.assertNotIn(999, {p["ProcessId"] for p in result})
        self.assertEqual(len([p for p in result if "CommandLine" in p]), 3)

    def test_unknown_metadata_does_not_open_other_capture_or_guess_by_mac(self):
        session = capture.CaptureSession(["S1-PC1", "S1-PC2"], HOSTS, capture.ROOT / "exp3/local/unused",
                                         candidates=[{"path": "unrelated.pcap", "pid": 999,
                                                      "mac": HOSTS["PC1"]["mac"]}])
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("no capture reads")):
            result = session.discover()
        self.assertTrue(result["needs_input"])
        self.assertEqual(set(result["mapping_template"]), {"S1-PC1", "S1-PC2"})

    def test_process_list_failure_returns_needs_input(self):
        def denied():
            raise OSError("fixture permission failure")
        result = capture.CaptureSession(["S1-PC1"], HOSTS, capture.ROOT / "exp3/local/unused",
                                        process_provider=denied).discover()
        self.assertEqual(result["status"], "needs_input")
        self.assertIn("permission", result["discovery_error"])

    def test_full_pipe_match_and_duplicate_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pcap"
            path.write_bytes(pcap_header())
            pipe = r"\\.\pipe\fixture\device-interface"
            candidates = [{"path": str(path), "interface": pipe, "pid": 100}]
            session = capture.CaptureSession(["S1-PC1"], HOSTS, capture.ROOT / "exp3/local/unused",
                                             candidates=candidates, link_metadata={"S1-PC1": {"interfaces": [pipe]}})
            result = session.discover()
            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["captures"][0]["pid"], 100)
            session = capture.CaptureSession(["S1-PC1", "S1-PC2"], HOSTS, capture.ROOT / "exp3/local/unused",
                                             candidates=candidates, mapping={"S1-PC1": str(path), "S1-PC2": str(path)})
            self.assertEqual(set(session.discover()["missing"]), {"S1-PC1", "S1-PC2"})

    def test_device_uuid_alone_never_matches_endpoint(self):
        endpoint = {"device_id": "ABC-123", "port_index": 0, "port": 1, "interface_name": "Ethernet0/0/1"}
        metadata = {"endpoints": [endpoint]}
        self.assertFalse(capture._interface_matches({"device_id": "ABC-123"}, metadata, "topology"))
        self.assertTrue(capture._interface_matches({"device_id": "{abc-123}", "port_index": 0}, metadata, "topology"))
        self.assertFalse(capture._interface_matches({"device_id": "ABC-123", "port_index": 1}, metadata, "topology"))
        self.assertFalse(capture._interface_matches({"device_id": "ABC-123", "port_index": 0,
                                                     "topology_id": "another"}, metadata, "topology"))

    def test_interface_metadata_requires_explicit_numbering_or_interface_name(self):
        uuid = "12345678-1234-1234-1234-123456789abc"
        pipe = "\\\\.\\pipe\\"
        bare = capture.interface_metadata(pipe + uuid + "_13")
        self.assertEqual(bare, {"device_id": uuid})
        tagged = capture.interface_metadata(pipe + uuid + ";port_index=13")
        self.assertEqual(tagged["port_index"], 13)
        name = capture.interface_metadata(pipe + uuid + "-Ethernet0/0/14")
        self.assertEqual(name["interface_name"], "Ethernet0/0/14")

    def test_windows_command_line_keeps_pipe_backslashes_and_unicode_paths(self):
        command = r'"C:\Program Files\Wireshark\dumpcap.exe" -i "\\.\pipe\capture\device" -w "C:\临时目录\active.pcap"'
        self.assertEqual(capture.command_option(command, "-i"), r"\\.\pipe\capture\device")
        self.assertEqual(capture.command_option(command, "-w"), r"C:\临时目录\active.pcap")

    def test_candidates_require_live_dumpcap_pid_and_do_not_read_files(self):
        with tempfile.TemporaryDirectory() as directory:
            valid = Path(directory) / "wireshark_fixturea123"
            valid.write_bytes(b"not read during discovery")
            (Path(directory) / "wireshark_othera999").write_bytes(b"unrelated")
            processes = [{"ProcessId": 123, "ParentProcessId": 10, "Name": "dumpcap.exe",
                          "CommandLine": r'dumpcap.exe -i "\\.\pipe\fixture"'},
                         {"ProcessId": 10, "Name": "Wireshark.exe", "CommandLine": "Wireshark.exe"}]
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("no read")):
                result = capture.discover_candidates(processes, directory)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["pid"], 123)
            self.assertEqual(result[0]["path"], str(valid.resolve()))


if __name__ == "__main__":
    unittest.main()
