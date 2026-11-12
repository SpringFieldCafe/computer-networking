"""模拟协议测试，不产生或宣称 eNSP 实测结果。"""
from collections import deque
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import collect_switches as c
from prepare_topology import generate_bundle, read_topology
from lab_spec import TOPOLOGY_FILES


def default_config():
    return 'sysname S1\n#\n'+'\n'.join(f'interface Ethernet0/0/{p}\n#' for p in range(1, 23))+'\nreturn'


def vlan2_config():
    return 'vlan batch 2\n'+'\n'.join(
        f'interface Ethernet0/0/{p}\n'+(' port link-type access\n port default vlan 2\n' if p >= 13 else '')+'#'
        for p in range(1, 23))


def core_config(routing=False):
    config = 'vlan batch 100 200\n'+'\n'.join(
        f'interface Ethernet0/0/{p}\n port link-type trunk\n port trunk allow-pass vlan 100 200\n#' for p in (1, 2))
    if routing:
        config += '\n'+'\n'.join(f'interface Vlanif{v}\n ip address 192.168.{v}.254 255.255.255.0\n#' for v in (100, 200))
    return config


class FakeSocket:
    def __init__(self, chunks=None, fail=None, config=None, name='S1', events=None):
        self.chunks = deque(chunks or [])
        self.sent = []
        self.fail = fail
        self.config = default_config() if config is None else config
        self.name, self.events = name, events

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, value):
        pass

    def sendall(self, data):
        self.sent.append(data)
        if self.events is not None:
            self.events.append((self.name, data))
        if self.chunks or data.startswith(b'\xff'):
            return
        cmd = data.decode('ascii').strip()
        body = 'VRP test fixture\r\n' if cmd == 'display version' else ''
        if cmd == 'display current-configuration':
            body = self.config+'\r\n'
        elif cmd == 'display vlan':
            body = 'VID Type Ports\r\n1 common\r\n2 common\r\n100 common\r\n200 common\r\n'
        if cmd == self.fail:
            body = 'Error: fixture rejected\r\n'
        self.chunks.append((cmd+'\r\n'+body+'<S1>').encode())

    def recv(self, size):
        if self.chunks:
            return self.chunks.popleft()
        raise socket.timeout()


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(c, 'runtime_guard', return_value={'kind': 'test fixture'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_telnet_fragmentation(self):
        sock = FakeSocket([b'\xff', b'\xfb', b'\x01hello\r\n<S1>'])
        self.assertIn('hello', c.read_prompt(sock, 0.02))
        self.assertEqual(sock.sent, [b'\xff\xfe\x01'])

    def test_pagination(self):
        sock = FakeSocket([b'row1\r\n---- Mo', b're ----', b'row2\r\n<S1>'])
        self.assertIn('row2', c.read_prompt(sock, 0.02))
        self.assertEqual(sock.sent, [b' '])

    def test_confirmation_not_answered(self):
        sock = FakeSocket([b'Change configuration? [Y/N]'])
        with self.assertRaises(c.ConsoleError):
            c.read_prompt(sock, 0.02)
        self.assertEqual(sock.sent, [])

    def test_disconnect_retains_output(self):
        sock = FakeSocket([b'partial', b''])
        with self.assertRaises(c.ConsoleError) as cm:
            c.read_prompt(sock, 0.02)
        self.assertEqual(cm.exception.partial, 'partial')

    def test_port_conflict_gates_before_connect(self):
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection') as connect:
            with self.assertRaisesRegex(ValueError, '用户确认'):
                c.collect('part1-vlan2', [2100], True)
            connect.assert_not_called()

    def test_output_cannot_escape_local(self):
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)):
            with self.assertRaisesRegex(ValueError, 'local'):
                c.collect('part1-default', [2100], output_root=Path(td)/'public')

    def test_readonly_does_not_send_configuration(self):
        sock = FakeSocket()
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection', return_value=sock):
            dest = c.collect('part1-default', [2100])
            info = json.loads((dest/'manifest.json').read_text(encoding='utf-8'))
            self.assertEqual(info['status'], 'configuration_verified')
        commands = [x.decode().strip() for x in sock.sent]
        self.assertNotIn('system-view', commands)
        self.assertIn('display mac-address', commands)

    def test_error_stops_and_keeps_diagnostics(self):
        sock = FakeSocket(fail='display vlan')
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection', return_value=sock):
            with self.assertRaises(c.ConsoleError):
                c.collect('part1-default', [2100])
            dest = next((Path(td)/'local'/'records').iterdir())
            self.assertIn('fixture rejected', (dest/'S1.txt').read_text(encoding='utf-8'))
            self.assertEqual(json.loads((dest/'manifest.json').read_text(encoding='utf-8'))['status'], 'failed')
        self.assertNotIn(b'display mac-address\r\n', sock.sent)

    def test_port_mismatch_detected(self):
        cfg = 'interface Ethernet0/0/13\n port link-type access\n port default vlan 3\n#'
        self.assertFalse(c.verify_config('part1-vlan2', 'S1', cfg)['configuration_ok'])

    def test_core_phase_distinction(self):
        cfg = core_config()
        self.assertTrue(c.verify_config('part2-l2-optional', 'S1', cfg)['configuration_ok'])
        self.assertFalse(c.verify_config('part2-access', 'S1', cfg)['configuration_ok'])
        self.assertFalse(c.verify_config('part2-routing', 'S1', cfg)['configuration_ok'])

    def test_vlan_range_and_routing_state(self):
        cfg = 'vlan batch 100 200\n'+'\n'.join(f'interface Ethernet0/0/{p}\n port link-type trunk\n port trunk allow-pass vlan 2 to 4094\n#' for p in (1, 2))
        cfg += '\n'+'\n'.join(f'interface Vlanif{v}\n ip address 192.168.{v}.254 255.255.255.0\n#' for v in (100, 200))
        brief = 'Vlanif100 192.168.100.254/24 up up\nVlanif200 192.168.200.254/24 up up'
        result = c.verify_config('part2-routing', 'S1', cfg, brief)
        self.assertTrue(result['configuration_ok'])
        self.assertFalse(result['operational_warnings'])

    def test_contexts_closed_and_no_clear_in_readonly(self):
        self.assertEqual(c.commands_for('part1-default', 'S1'), [])
        self.assertEqual(c.commands_for('part2-access', 'S1'), [])
        cmds = c.commands_for('part2-routing', 'S1')
        self.assertEqual(cmds[-1], 'return')
        self.assertEqual(cmds.count('quit'), 4)
        self.assertNotIn('reset arp all', cmds)

    def test_default_baseline_checks_even_unused_ports(self):
        cfg = default_config().replace('interface Ethernet0/0/15\n#',
                                       'interface Ethernet0/0/15\n port link-type access\n port default vlan 2\n#')
        self.assertFalse(c.verify_config('part1-default', 'S1', cfg)['configuration_ok'])

    def test_empty_configuration_never_verified(self):
        for stage, name in [('part1-default', 'S1'), ('part2-access', 'S1'), ('part2-routing', 'S2')]:
            with self.subTest(stage=stage):
                self.assertFalse(c.verify_config(stage, name, '')['configuration_ok'])
        sock = FakeSocket(config='')
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection', return_value=sock):
            with self.assertRaises(c.ConsoleError):
                c.collect('part1-default', [2100])
            manifest = next((Path(td)/'local'/'records').glob('*/manifest.json'))
            self.assertEqual(json.loads(manifest.read_text(encoding='utf-8'))['status'], 'failed')

    def test_default_baseline_rejects_mode_and_vlan_contamination(self):
        additions = ['port link-type trunk\n port trunk allow-pass vlan all',
                     'port link-type access\n port default vlan 100',
                     'port link-type hybrid\n port hybrid tagged vlan 100 200',
                     'port hybrid pvid vlan 100', 'port hybrid untagged vlan 100']
        for stage in ('part1-default', 'part2-access'):
            self.assertTrue(c.verify_config(stage, 'S1', default_config())['configuration_ok'])
            for extra in additions:
                cfg = default_config().replace('interface Ethernet0/0/1\n#', 'interface Ethernet0/0/1\n '+extra+'\n#')
                with self.subTest(stage=stage, extra=extra):
                    self.assertFalse(c.verify_config(stage, 'S1', cfg)['configuration_ok'])

    def test_vlans_and_gateway_need_readback(self):
        cfg = core_config(True)
        self.assertFalse(c.verify_config('part2-routing', 'S1', cfg.replace('vlan batch 100 200', ''))['configuration_ok'])
        self.assertFalse(c.verify_config('part2-routing', 'S1', cfg.replace('192.168.100.254', '192.168.100.253'))['configuration_ok'])
        self.assertFalse(c.verify_config('part2-routing', 'S1', cfg, vlan_output='')['configuration_ok'])
        self.assertFalse(c.verify_config('part2-routing', 'S1', cfg, vlan_output='100 common')['configuration_ok'])
        self.assertTrue(c.verify_config('part2-routing', 'S1', cfg, vlan_output='100 common\n200 common')['configuration_ok'])
        self.assertFalse(c.verify_config('part2-l2-optional', 'S1', core_config()+'\ninterface Vlanif100\n#')['configuration_ok'])

    def test_user_confirmed_ethernet_gate_allows_apply(self):
        sock = FakeSocket(config=vlan2_config())
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection', return_value=sock):
            decision = Path(td)/'local'/'state'/'decisions.json'
            decision.parent.mkdir(parents=True)
            decision.write_text(json.dumps({'port_range': {'status': 'confirmed', 'interface': 'Ethernet', 'note': 'user fixture'}}))
            dest = c.collect('part1-vlan2', [2100], True)
            self.assertEqual(json.loads((dest/'manifest.json').read_text(encoding='utf-8'))['status'], 'configuration_verified')
        self.assertIn(b'port default vlan 2\r\n', sock.sent)

    def test_unconfirmed_or_ge_decision_does_not_connect(self):
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection') as connect:
            decision = Path(td)/'local'/'state'/'decisions.json'
            decision.parent.mkdir(parents=True)
            for value in [{'status': 'unresolved', 'interface': 'Ethernet'}, {'status': 'confirmed', 'interface': 'GE'}]:
                decision.write_text(json.dumps({'port_range': value}))
                with self.assertRaises(ValueError):
                    c.collect('part1-vlan2', [2100], True)
            connect.assert_not_called()

    def test_all_devices_preflight_before_any_configuration(self):
        events = []
        sockets = [FakeSocket(name='S1', events=events), FakeSocket(name='S2', events=events),
                   FakeSocket(name='S3', events=events, fail='display current-configuration')]
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection', side_effect=sockets):
            with self.assertRaises(c.ConsoleError):
                c.collect('part2-routing', [2200, 2201, 2202], True)
        self.assertFalse(any(data == b'system-view\r\n' for _, data in events))
        self.assertEqual({name for name, data in events if data == b'display version\r\n'}, {'S1', 'S2', 'S3'})

    def test_polluted_core_is_rejected_before_access_switch_changes(self):
        polluted = default_config().replace('interface Ethernet0/0/1\n#', 'interface Ethernet0/0/1\n port link-type access\n port default vlan 100\n#')
        sock = FakeSocket(config=polluted)
        with tempfile.TemporaryDirectory() as td, patch.object(c, 'ROOT', Path(td)), patch.object(c.socket, 'create_connection', return_value=sock):
            with self.assertRaises(c.ConsoleError):
                c.collect('part2-access', [2200, 2201, 2202], True)
        self.assertNotIn(b'system-view\r\n', sock.sent)

    def test_connection_reset_retains_partial_response(self):
        class ResetSocket(FakeSocket):
            def recv(self, size):
                if self.chunks:
                    return self.chunks.popleft()
                raise ConnectionResetError('TEST RESET')
        with self.assertRaises(c.ConsoleError) as cm:
            c.read_prompt(ResetSocket([b'partial evidence']))
        self.assertEqual(cm.exception.partial, 'partial evidence')


class RuntimeGuardTests(unittest.TestCase):
    """真实临时工程/资源目录；仅模拟系统进程查询，不启动或连接eNSP。"""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle, _ = generate_bundle(self.root/'local'/'topology', run_id='guard-fixture')
        self.appdata = self.root/'appdata'
        self.workspace = self.appdata/'eNSP'/'VBoxServer'/'workspaces'
        self.devices = read_topology(self.bundle/TOPOLOGY_FILES['part2']).findall('./devices/dev')[:3]
        self.configs = []
        for dev in self.devices:
            path = self.workspace/dev.get('id')/'slot17'/'hardcfg.tcl'
            path.parent.mkdir(parents=True)
            path.write_text('SetDeviceID '+dev.get('id')+'\n', encoding='utf-8')
            self.configs.append(path)
        self.rows = [{'Port': port, 'PID': 12345, 'Name': 'eNSP_Client'} for port in (2200, 2201, 2202)]
        for patcher in (patch.object(c, 'ROOT', self.root), patch.dict(c.os.environ, {'LOCALAPPDATA': str(self.appdata)}),
                        patch.object(c.sys, 'platform', 'win32')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def guard(self, ports=None, rows=None):
        completed = subprocess.CompletedProcess([], 0, json.dumps(self.rows if rows is None else rows).encode(), b'')
        with patch.object(c.subprocess, 'run', return_value=completed):
            return c.runtime_guard('part2-access', ports or [2200, 2201, 2202], self.bundle)

    def test_checks_hash_ids_owner_without_claiming_live_id_binding(self):
        result = self.guard()
        self.assertTrue(result['manifest_ids_verified'])
        self.assertTrue(result['same_console_process_verified'])
        self.assertFalse(result['live_device_id_binding_verified'])
        self.assertIn('运行待核', result['runtime_identity_status'])

    def test_changed_topology_hash_is_refused(self):
        path = self.bundle/TOPOLOGY_FILES['part2']
        path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError, '哈希'):
            self.guard()

    def test_manifest_wrong_id_is_refused(self):
        path = self.bundle/'manifest.json'
        manifest = json.loads(path.read_text(encoding='utf-8'))
        manifest['device_ids']['part2']['S1'] = 'WRONG-ID'
        path.write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'manifest'):
            self.guard()

    def test_wrong_console_ports_are_refused(self):
        with self.assertRaisesRegex(ValueError, '端口'):
            self.guard([2200, 2201, 2203])

    def test_missing_or_wrong_resource_id_is_refused(self):
        self.configs[0].write_text('SetDeviceID WRONG-ID\n')
        with self.assertRaisesRegex(ValueError, '运行资源'):
            self.guard()
        self.configs[0].unlink()
        with self.assertRaisesRegex(ValueError, '运行资源'):
            self.guard()

    def test_foreign_or_split_ensp_owner_is_refused(self):
        for owner in [{'Name': 'OtherProcess'}, {'PID': 54321}]:
            rows = [dict(row) for row in self.rows]
            rows[-1].update(owner)
            with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, '进程归属'):
                self.guard(rows=rows)
        with self.assertRaisesRegex(ValueError, '进程归属'):
            self.guard(rows=self.rows[:-1])

    def test_guard_failure_precedes_all_console_connections(self):
        self.configs[0].unlink()
        with patch.object(c.socket, 'create_connection') as connect:
            with self.assertRaises(c.ConsoleError):
                c.collect('part2-access', [2200, 2201, 2202], True, bundle=self.bundle)
            connect.assert_not_called()
        path = next((self.root/'local'/'records').glob('*/manifest.json'))
        self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
