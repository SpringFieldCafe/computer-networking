"""校验课件映射与会破坏工程的实际错误；测试不启动 eNSP。"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from lab_spec import TOPOLOGY_FILES, EXPERIMENTS, EXP1_LINKS, EXP2_LINKS, STAGES, expected_pc1, theoretical_matrix, validate_spec
from prepare_topology import build_topology, generate_bundle, load_port_range_decision, read_topology, validate_topology


class TopologyTests(unittest.TestCase):
    def test_course_mapping(self):
        self.assertEqual(EXP1_LINKS, (("S1", 1, "PC1", 1), ("S1", 2, "PC2", 1),
                                    ("S1", 13, "PC3", 1), ("S1", 14, "PC4", 1)))
        self.assertEqual(EXP2_LINKS, (("S1", 1, "S2", 3), ("S1", 2, "S3", 3),
                                    ("S2", 1, "PC1", 1), ("S2", 2, "PC2", 1),
                                    ("S3", 1, "PC3", 1), ("S3", 2, "PC4", 1)))

    def test_both_native_models_and_unique_ids(self):
        all_ids = []
        for experiment, expected_count in (("part1", 5), ("part2", 7)):
            root = build_topology(experiment)
            self.assertEqual(validate_topology(root, experiment)["devices"], expected_count)
            devices = root.findall("./devices/dev")
            self.assertEqual(sum(d.get("model") == "PC" for d in devices), 4)
            for dev in devices:
                if dev.get("model") == "PC":
                    self.assertIn("-simpc_ip " + EXPERIMENTS[experiment]["hosts"][dev.get("name")]["ip"], dev.get("settings"))
            all_ids.extend(d.get("id") for d in devices)
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_reject_duplicate_id(self):
        root = build_topology("part1")
        devices = root.findall("./devices/dev")
        devices[1].set("id", devices[0].get("id"))
        with self.assertRaisesRegex(ValueError, "ID.*重复"):
            validate_topology(root, "part1")

    def test_new_build_does_not_reuse_device_cache_ids(self):
        first = {d.get("id") for d in build_topology("part2").findall("./devices/dev")}
        second = {d.get("id") for d in build_topology("part2").findall("./devices/dev")}
        self.assertFalse(first & second)

    def test_reject_reused_port(self):
        root = build_topology("part1")
        root.findall("./lines/line/interfacePair")[1].set("srcIndex", "0")
        with self.assertRaisesRegex(ValueError, "复用"):
            validate_topology(root, "part1")

    def test_reject_out_of_range_pc_port(self):
        root = build_topology("part1")
        root.find("./lines/line/interfacePair").set("tarIndex", "1")
        with self.assertRaisesRegex(ValueError, "越界"):
            validate_topology(root, "part1")

    def test_reject_wrong_but_unused_switch_port(self):
        root = build_topology("part1")
        root.findall("./lines/line/interfacePair")[-1].set("srcIndex", "14")
        with self.assertRaisesRegex(ValueError, "映射"):
            validate_topology(root, "part1")

    def test_reject_wrong_model_and_parameters(self):
        for attribute, value in (("model", "Client"), ("settings", ""), ("com_port", "2100")):
            root = build_topology("part1")
            root.findall("./devices/dev")[1].set(attribute, value)
            with self.assertRaises(ValueError):
                validate_topology(root, "part1")

    def test_reject_spec_port_reuse(self):
        spec = copy.deepcopy(EXPERIMENTS["part2"])
        spec["links"] = spec["links"] + (("S2", 1, "PC3", 1),)
        with self.assertRaisesRegex(ValueError, "复用"):
            validate_spec("part2", spec)

    def test_reject_ip_duplicate(self):
        spec = copy.deepcopy(EXPERIMENTS["part1"])
        spec["hosts"]["PC2"]["ip"] = spec["hosts"]["PC1"]["ip"]
        with self.assertRaisesRegex(ValueError, "IP.*重复"):
            validate_spec("part1", spec)

    def test_all_stage_theoretical_matrices(self):
        expected = {
            "part1-default": (True, True, True), "part1-vlan2": (True, False, False),
            "part2-access": (False, False, False), "part2-l2-optional": (False, True, False),
            "part2-routing": (True, True, True),
        }
        expected_successes = {"part1-default": 12, "part1-vlan2": 4, "part2-access": 0,
                              "part2-l2-optional": 4, "part2-routing": 12}
        for stage in STAGES:
            matrix = theoretical_matrix(stage)
            self.assertEqual(tuple(expected_pc1(stage).values()), expected[stage])
            self.assertEqual(len(matrix), 12)
            self.assertEqual(sum(matrix.values()), expected_successes[stage])
            self.assertTrue(all(matrix[(a, b)] == matrix[(b, a)] for a, b in matrix))

    def test_exclusive_generation_and_read_only_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            destination, configs = generate_bundle(base / "topology", base / "config", "test-batch")
            topo = destination / TOPOLOGY_FILES["part2"]
            before = hashlib.sha256(topo.read_bytes()).digest()
            self.assertEqual(validate_topology(read_topology(topo), "part2")["links"], 6)
            self.assertEqual(before, hashlib.sha256(topo.read_bytes()).digest())
            self.assertTrue((configs / "part2-routing" / "S1.txt").is_file())
            with self.assertRaises(FileExistsError):
                generate_bundle(base / "topology", base / "config", "test-batch")
            self.assertEqual(before, hashlib.sha256(topo.read_bytes()).digest())

    def test_reject_output_path_escape(self):
        with self.assertRaises(ValueError):
            generate_bundle(run_id="../escape")

    def test_default_config_is_inside_local_bundle_and_manifest_ids_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination, configs = generate_bundle(Path(tmp), run_id="local-batch", decisions_path=Path(tmp) / "missing.json")
            self.assertEqual(configs, destination / "config")
            manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
            root = read_topology(destination / TOPOLOGY_FILES["part1"])
            validate_topology(root, "part1", manifest)
            manifest["device_ids"]["part1"]["S1"] = "wrong-batch"
            with self.assertRaisesRegex(ValueError, "manifest"):
                validate_topology(root, "part1", manifest)
            self.assertEqual(manifest["pending_decisions"][0]["status"], "unresolved")
            self.assertFalse(manifest["reference_configs_enabled"])
            self.assertIn("CANDIDATE", (configs / "part1-vlan2" / "S1.txt").read_text(encoding="ascii"))

    def test_user_confirmation_updates_manifest_config_and_notes_without_editing_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            decision = {"status": "confirmed", "interface": "Ethernet", "source": "user",
                        "note": "测试夹具：确认按P8/P10处理", "recorded_at": "2000-01-01T20:00:00+08:00"}
            state = base / "decisions.json"
            state.write_text(json.dumps({"port_range": decision}, ensure_ascii=False), encoding="utf-8")
            before = state.read_bytes()
            destination, configs = generate_bundle(base / "topology", run_id="confirmed-batch", decisions_path=state)
            manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["port_range_decision"], decision)
            self.assertEqual(manifest["pending_decisions"], [])
            self.assertIn("用户确认", manifest["port_resolution"])
            self.assertNotIn("pending_decision", manifest["stages"]["part1-vlan2"])
            self.assertNotIn("候选", manifest["stages"]["part1-vlan2"]["description"])
            config = (configs / "part1-vlan2" / "S1.txt").read_text(encoding="ascii")
            self.assertIn("CONFIRMED BY USER", config)
            self.assertNotIn("CANDIDATE", config)
            self.assertIn("NOT APPLIED", config)
            notes = (destination / "preparation_notes.txt").read_text(encoding="utf-8")
            self.assertIn("确认来源为用户", notes)
            self.assertNotIn("待老师确认", notes)
            self.assertFalse(manifest["runtime_verified"])
            self.assertEqual(state.read_bytes(), before)

    def test_unconfirmed_state_keeps_candidate_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = base / "decisions.json"
            state.write_text(json.dumps({"port_range": {"status": "pending", "source": "user"}}), encoding="utf-8")
            self.assertEqual(load_port_range_decision(state)["status"], "unresolved")
            destination, configs = generate_bundle(base / "topology", run_id="pending-batch", decisions_path=state)
            manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["pending_decisions"][0]["status"], "unresolved")
            self.assertIn("CANDIDATE", (configs / "part1-vlan2" / "S1.txt").read_text(encoding="ascii"))

    def test_reject_confirmation_with_other_interface_or_unrecorded_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = base / "decisions.json"
            for decision in ({"status": "confirmed", "interface": "GE", "source": "user"},
                             {"status": "confirmed", "interface": "Ethernet"}):
                state.write_text(json.dumps({"port_range": decision}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    generate_bundle(base / "topology", run_id="rejected-batch", decisions_path=state)
                self.assertFalse((base / "topology" / "rejected-batch").exists())


if __name__ == "__main__":
    unittest.main()
