"""FakeNative 模拟接口测试；没有运行 eNSP，也没有真实 ICMP 结果。"""
from dataclasses import replace
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import pc_console as pc


HOSTS = {
    f'PC{number}': {'ip': f'192.168.100.{number}', 'mac': f'02-00-00-03-02-{number:02X}',
                    'gateway': '192.168.100.254', 'mask': '255.255.255.0'}
    for number in range(1, 5)
}


def ipconfig_text(host):
    return ('IP Configuration\r\n\r\nIPv4 address......................: ' + host['ip']
            + '\r\nSubnet mask.......................: ' + host['mask']
            + '\r\nGateway...........................: ' + host['gateway']
            + '\r\nPhysical address..................: ' + host['mac'] + '\r\n\r\nPC>')


def ping_text(target, sent=4, received=4, legacy_reply=False):
    lines = ['Ping ' + target + ': 32 data bytes, Press Ctrl_C to break']
    for seq in range(1, received + 1):
        if legacy_reply:
            lines.append(f'Reply from {target}: bytes=32 seq={seq} TTL=128 time<1 ms')
        else:
            lines.append(f'From {target}: bytes=32 seq={seq} ttl=128 time<1 ms')
    for _ in range(sent - received):
        lines.append('Request timeout!')
    lines += ['', f'--- {target} ping statistics ---', f'  {sent} packet(s) transmitted',
              f'  {received} packet(s) received', '  0.00% packet loss', '', 'PC>']
    return '\r\n'.join(lines)


class FakeNative:
    def __init__(self):
        self.image = r'C:\Program Files\Huawei\eNSP\eNSP_Client.exe'
        self.commands, self.interrupts, self.shots = [], [], []
        self.output = {}
        self.rows = []
        self.source_of = {}
        self.actual_hosts = {name: dict(h) for name, h in HOSTS.items()}
        self.responses = {}
        self.stop_returns_prompt = False
        self.raise_screenshot = False
        for i, name in enumerate(HOSTS):
            root, control = 0x100000001 + i * 4, 0x100000002 + i * 4
            self.rows += [pc.Window(root, 0, 73, name, '#32770', 0, True, True),
                          pc.Window(control, root, 73, '', 'RichEdit20A', 1084, True, True)]
            self.source_of[control] = name
            self.output[control] = 'Welcome to use PC Simulator!\r\n\r\nPC>'

    def process_image(self):
        return self.image

    def windows(self):
        return self.rows

    def text(self, hwnd):
        return self.output[hwnd]

    def submit(self, hwnd, command, before):
        self.commands.append((self.source_of[hwnd], command))
        custom = self.responses.get(command)
        if callable(custom):
            self.output[hwnd] = custom(before)
        elif custom is not None:
            self.output[hwnd] += command + '\r\n' + custom
        elif command == 'ipconfig':
            self.output[hwnd] += command + '\r\n' + ipconfig_text(self.actual_hosts[self.source_of[hwnd]])
        elif command.startswith('ping '):
            self.output[hwnd] += command + '\r\n' + ping_text(command.split()[1])
        elif command == 'arp -d *':
            self.output[hwnd] += command + '\r\n\r\nPC>'
        elif command == 'arp -a':
            self.output[hwnd] += command + '\r\nInternet Address    Physical Address    Type\r\n\r\nPC>'
        else:
            raise AssertionError('不允许测试夹具以外的命令: ' + command)

    def interrupt(self, hwnd):
        self.interrupts.append(hwnd)
        if self.stop_returns_prompt:
            self.output[hwnd] += '\r\nPC>'

    def screenshot(self, hwnd, destination):
        self.shots.append(hwnd)
        if self.raise_screenshot:
            raise OSError('模拟截图失败')
        return {'path': None, 'missing': 'TEST FIXTURE: 不生成 eNSP 截图'}


class PCConsoleTests(unittest.TestCase):
    def setUp(self):
        pc.LOCAL.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='pc-console-test-', dir=pc.LOCAL)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.native = FakeNative()
        self.console = pc.PCConsole(73, HOSTS, native=self.native, timeout=.05)

    def ready(self, names=('PC1',)):
        result = self.console.probe(names, self.directory)
        self.assertEqual(result['status'], 'ready')
        return result

    def ping(self, **kwargs):
        return self.console.ping('PC1', HOSTS['PC2']['ip'], output_dir=self.directory, **kwargs)

    def test_only_required_sources_are_opened_and_pid_width_preserved(self):
        self.native.rows = [r for r in self.native.rows if r.hwnd <= 0x100000002]
        result = self.ready()
        self.assertEqual(set(result['hosts']), {'PC1'})
        self.assertGreater(result['hosts']['PC1']['window_handle'], 2**32)
        self.assertTrue(result['hosts']['PC1']['verified_ip'])
        self.assertTrue(result['hosts']['PC1']['verified_mac'])

    def test_all_required_windows_prechecked_before_any_command(self):
        self.native.rows = [r for r in self.native.rows if r.title != 'PC3']
        result = self.console.probe(['PC1', 'PC2', 'PC3'], self.directory)
        self.assertEqual(result['status'], 'needs_input')
        self.assertEqual(result['missing'], ['PC3'])
        self.assertEqual(self.native.commands, [])
        with self.assertRaises(pc.PCConsoleError):
            self.ping()

    def test_console_page_id1154_is_never_used_for_simpc(self):
        self.native.rows = [replace(r, control_id=1154) if r.control_id == 1084 else r for r in self.native.rows]
        self.assertEqual(self.console.probe(['PC1'], self.directory)['status'], 'needs_input')
        self.assertEqual(self.native.commands, [])

    def test_wrong_process_or_control_owner_rejected(self):
        self.native.image = r'C:\Windows\System32\cmd.exe'
        self.assertEqual(self.console.probe(['PC1'], self.directory)['status'], 'needs_input')
        self.assertEqual(self.native.commands, [])
        self.native.image = r'C:\Program Files\Huawei\eNSP\eNSP_Client.exe'
        self.native.rows = [replace(r, pid=999) if r.control_id else r for r in self.native.rows]
        self.assertEqual(self.console.probe(['PC1'], self.directory)['status'], 'needs_input')

    def test_duplicate_pc_window_rejected(self):
        root, control = self.native.rows[:2]
        self.native.rows += [replace(root, hwnd=7), replace(control, hwnd=8, parent=7)]
        self.assertEqual(self.console.probe(['PC1'], self.directory)['status'], 'needs_input')

    def test_ip_mismatch_prevents_ping(self):
        self.native.actual_hosts['PC1']['ip'] = HOSTS['PC2']['ip']
        result = self.console.probe(['PC1'], self.directory)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['hosts']['PC1']['verified_ip'])
        with self.assertRaises(pc.PCConsoleError):
            self.ping()
        self.assertFalse(any(cmd.startswith('ping') for _, cmd in self.native.commands))

    def test_mac_mismatch_after_probe_rechecked_before_emission(self):
        self.ready()
        self.native.actual_hosts['PC1']['mac'] = HOSTS['PC2']['mac']
        with self.assertRaises(pc.PCConsoleError):
            self.ping()
        self.assertFalse(any(cmd.startswith('ping') for _, cmd in self.native.commands))

    def test_mask_or_gateway_mismatch_prevents_emission(self):
        for field, value in [('mask', '255.255.0.0'), ('gateway', '192.168.100.253')]:
            with self.subTest(field=field):
                self.native = FakeNative()
                self.console = pc.PCConsole(73, HOSTS, native=self.native)
                self.native.actual_hosts['PC1'][field] = value
                result = self.console.probe(['PC1'], self.directory)
                self.assertEqual(result['status'], 'failed')
                self.assertFalse(result['hosts']['PC1']['verified_' + field])
                self.assertFalse(any(cmd.startswith('ping') for _, cmd in self.native.commands))

    def test_hidden_windows_allowed_when_native_identity_and_echo_verified(self):
        self.native.rows = [replace(row, visible=False) for row in self.native.rows]
        self.ready()
        self.assertEqual(self.ping()['status'], 'completed')

    def test_input_not_accepted_preserves_failure_without_enter_or_cancel(self):
        error = pc.PCConsoleError('命令输入回读不一致；尚未自动按 Enter', {'enter_sent': False})
        with patch.object(self.native, 'submit', side_effect=error):
            result = self.console.ipconfig('PC1', self.directory)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('回读不一致', result['error'])
        self.assertFalse(result['enter_sent'])
        self.assertFalse(result['manual_stop_required'])
        self.assertFalse(self.native.interrupts)
        self.assertEqual(result['raw_text'], '')

    def test_target_and_count_validation_before_command(self):
        self.ready()
        count_before = len(self.native.commands)
        for ip in ('8.8.8.8', '127.0.0.1', '0.0.0.0', '192.168.100.2 & whoami'):
            with self.assertRaises(ValueError):
                self.console.ping('PC1', ip, output_dir=self.directory)
        for count in (0, 5, True, '4'):
            with self.assertRaises(ValueError):
                self.ping(count=count)
        self.assertEqual(len(self.native.commands), count_before)

    def test_gateway_target_permitted(self):
        self.ready()
        result = self.console.ping('PC1', HOSTS['PC1']['gateway'], output_dir=self.directory)
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['target_verified'])

    def test_actual_labeled_raw_output_and_missing_screenshot(self):
        self.ready()
        result = self.ping()
        self.assertEqual((result['status'], result['sent'], result['received'], result['unknown']),
                         ('completed', 4, 4, False))
        self.assertEqual(result['command'], 'ping 192.168.100.2 -c 4 -w 1000')
        self.assertTrue(result['verified_ip'] and result['verified_mac'])
        self.assertIsNone(result['screenshot'])
        self.assertIn('TEST FIXTURE', result['screenshot_missing'])
        self.assertTrue(Path(result['raw_file']).is_file())
        self.assertTrue(Path(result['raw_file']).with_suffix('.json').is_file())
        self.assertTrue(result['after_text'].startswith(result['before_text']))
        self.assertEqual(result['raw_text'], result['after_text'][len(result['before_text']):])
        self.assertEqual(self.native.shots[-1], result['control_handle'])
        self.assertEqual(result['screenshot_window_handle'], result['control_handle'])
        self.assertNotEqual(result['screenshot_window_handle'], result['window_handle'])

    def test_historical_success_does_not_contaminate_current_loss(self):
        self.ready()
        control = self.native.rows[1].hwnd
        self.native.output[control] += '\r\n' + ping_text(HOSTS['PC2']['ip'])
        command = 'ping 192.168.100.2 -c 4 -w 1000'
        self.native.responses[command] = ping_text(HOSTS['PC2']['ip'], received=0)
        result = self.ping()
        self.assertEqual((result['sent'], result['received'], result['timeout_lines'], result['unknown']), (4, 0, 4, False))
        self.assertEqual(result['reply_lines'], [])

    def test_rewrite_boundary_cannot_yield_success(self):
        self.ready()
        self.native.responses['ping 192.168.100.2 -c 4 -w 1000'] = lambda _: ping_text(HOSTS['PC2']['ip'])
        result = self.ping()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['boundary_verified'])
        self.assertTrue(result['unknown'])
        self.assertEqual(result['raw_text'], '')

    def test_timeout_attempts_cancel_once_and_never_retries(self):
        self.ready()
        self.native.responses['ping 192.168.100.2 -c 4 -w 1000'] = 'Ping 192.168.100.2: 32 data bytes\r\n'
        result = self.ping()
        self.assertEqual(result['status'], 'timeout')
        self.assertTrue(result['manual_stop_required'])
        self.assertTrue(result['unknown'])
        self.assertIsNone(result['sent'])
        self.assertEqual(len(self.native.interrupts), 1)
        with self.assertRaises(pc.PCConsoleError):
            self.ping()
        self.assertEqual(sum(cmd.startswith('ping ') for _, cmd in self.native.commands), 1)

    def test_timeout_with_prompt_confirms_stop_but_still_does_not_retry(self):
        self.ready()
        self.native.stop_returns_prompt = True
        self.native.responses['ping 192.168.100.2 -c 4 -w 1000'] = 'Ping 192.168.100.2: 32 data bytes\r\n'
        result = self.ping()
        self.assertEqual(result['status'], 'timeout')
        self.assertFalse(result['manual_stop_required'])
        self.assertTrue(self.console.blocked)

    def test_lost_required_window_prevents_emission(self):
        self.ready(('PC1', 'PC2', 'PC3'))
        self.native.rows = [r for r in self.native.rows if r.title != 'PC3']
        with self.assertRaises(pc.PCConsoleError):
            self.ping()
        self.assertFalse(any(cmd.startswith('ping') for _, cmd in self.native.commands))

    def test_output_directory_must_stay_local(self):
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaises(ValueError):
                self.console.ping('PC1', HOSTS['PC2']['ip'], output_dir=Path(outside))
        self.assertEqual(self.native.commands, [])

    def test_missing_mac_configuration_rejected(self):
        hosts = {name: dict(h) for name, h in HOSTS.items()}
        del hosts['PC1']['mac']
        with self.assertRaises(ValueError):
            pc.PCConsole(73, hosts, native=self.native)

    def test_arp_clear_verified_by_real_style_readback(self):
        self.ready()
        result = self.console.clear_arp('PC1', self.directory)
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['verified_clear'])
        self.assertEqual(self.native.commands[-2:], [('PC1', 'arp -d *'), ('PC1', 'arp -a')])

    def test_arp_entry_remaining_or_help_is_unverified(self):
        self.ready()
        self.native.responses['arp -a'] = ('Internet Address    Physical Address    Type\r\n'
                                          '192.168.100.2     02-00-00-03-02-02   dynamic\r\nPC>')
        result = self.console.clear_arp('PC1', self.directory)
        self.assertFalse(result['verified_clear'])
        self.assertEqual(result['status'], 'clear_unverified')
        self.native.responses['arp -a'] = 'Usage: arp [-a]\r\nPC>'
        result = self.console.clear_arp('PC1', self.directory)
        self.assertFalse(result['verified_clear'])

    def test_arp_malformed_target_row_is_not_mistaken_for_empty_table(self):
        self.ready()
        self.native.responses['arp -a'] = ('Internet Address    Physical Address    Type\r\n'
                                          '192.168.100.254     Incomplete\r\nPC>')
        result = self.console.clear_arp('PC1', self.directory)
        self.assertFalse(result['verified_clear'])

    def test_concurrent_input_echo_boundary_is_rejected(self):
        self.ready()
        self.native.responses['ping 192.168.100.2 -c 4 -w 1000'] = lambda before: (
            before + 'ping 192.168.100.2 -c 4 -w 1000EXTRA\r\n' + ping_text('192.168.100.2'))
        result = self.ping()
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['unknown'])

    def test_screenshot_exception_preserves_actual_text_and_missing_item(self):
        self.ready()
        self.native.raise_screenshot = True
        result = self.ping()
        self.assertEqual(result['received'], 4)
        self.assertIsNone(result['screenshot'])
        self.assertIn('待用户现场截图', result['screenshot_missing'])

    def test_nonempty_input_line_rejected_without_command(self):
        self.ready()
        self.native.output[self.native.rows[1].hwnd] += 'pending text'
        before = len(self.native.commands)
        with self.assertRaises(pc.PCConsoleError):
            self.ping()
        self.assertEqual(len(self.native.commands), before)


class ParsingTests(unittest.TestCase):
    def test_four_installed_dll_statistics_layouts(self):
        # 根据本机四个原生格式构造测试输入，不是网络运行结果。
        summaries = [
            (0, '  100.00% packet loss\n\nPC>'),
            (4, '  0.00% packet loss\n  round-trip min/avg/max = 0/0/0 ms\n\nPC>'),
            (3, '  25.00% packet loss\n  round-trip min/avg/max = 1/2/3 ms\n\nPC>'),
            (4, '  0.00% packet loss\n\nPC>'),
        ]
        for count, suffix in summaries:
            replies = ''.join(f'From 192.168.100.2: bytes=32 seq={i} ttl=128 time<1 ms\n' for i in range(1, count + 1))
            text = ('Ping 192.168.100.2: 32 data bytes, Press Ctrl_C to break\n'
                    + replies + '\n--- 192.168.100.2 ping statistics ---\n'
                    + f'  4 packet(s) transmitted\n  {count} packet(s) received\n' + suffix)
            with self.subTest(received=count, suffix=suffix):
                result = pc.parse_ping(text, '192.168.100.2', 4)
                self.assertFalse(result['unknown'])
                self.assertEqual((result['sent'], result['received']), (4, count))

    def test_from_and_reply_variants(self):
        for legacy in (False, True):
            result = pc.parse_ping(ping_text('192.168.100.2', legacy_reply=legacy), '192.168.100.2', 4)
            self.assertFalse(result['unknown'])
            self.assertEqual(result['received'], 4)

    def test_bad_summary_or_duplicate_reply_stays_unknown(self):
        text = ping_text('192.168.100.2')
        variants = [text.replace('seq=2', 'seq=1'), text.replace('4 packet(s) received', '3 packet(s) received'),
                    text.replace('--- 192.168.100.2', '--- 192.168.100.3'),
                    text + '\r\n 4 packet(s) received']
        for data in variants:
            self.assertTrue(pc.parse_ping(data, '192.168.100.2', 4)['unknown'])

    def test_incomplete_statistics_never_fills_guessed_counts(self):
        data = 'Ping 192.168.100.2: 32 data bytes\r\nRequest timeout!\r\nPC>'
        result = pc.parse_ping(data, '192.168.100.2', 4)
        self.assertIsNone(result['sent'])
        self.assertIsNone(result['received'])
        self.assertTrue(result['unknown'])

    def test_unreachable_counts_do_not_count_as_replies(self):
        text = ping_text('192.168.100.2', received=0).replace('Request timeout!', 'From 192.168.100.254: Destination host unreachable')
        result = pc.parse_ping(text, '192.168.100.2', 4)
        self.assertEqual(result['unreachable_lines'], 4)
        self.assertFalse(result['unknown'])
        self.assertEqual(result['reply_lines'], [])

    def test_ipconfig_requires_both_labelled_ipv4_and_mac(self):
        text = ipconfig_text(HOSTS['PC1'])
        self.assertTrue(pc.parse_ipconfig(text, HOSTS['PC1'])['verified_ip'])
        self.assertTrue(pc.parse_ipconfig(text.lower(), HOSTS['PC1'])['verified_mac'])
        self.assertFalse(pc.parse_ipconfig('192.168.100.1 ' + HOSTS['PC1']['mac'], HOSTS['PC1'])['verified_ip'])

    def test_part1_blank_or_none_gateway_and_required_mask(self):
        host = dict(HOSTS['PC1'], gateway='0.0.0.0')
        for gateway in ('0.0.0.0', '', 'None', 'none', '-'):
            result = pc.parse_ipconfig(ipconfig_text(dict(host, gateway=gateway)), host)
            self.assertTrue(result['verified_gateway'])
            self.assertTrue(result['verified_mask'])
        bad = pc.parse_ipconfig(ipconfig_text(dict(host, gateway='192.168.100.254')), host)
        self.assertFalse(bad['verified_gateway'])
        missing = pc.parse_ipconfig(ipconfig_text(host).replace('Gateway', 'Missing'), host)
        self.assertFalse(missing['verified_gateway'])

    def test_png_writes_only_real_pixels_and_rejects_blank(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'test.png'
            with self.assertRaises(pc.PCConsoleError):
                pc._write_png(path, 2, 2, b'\0' * 16)
            self.assertFalse(path.exists())
            pixels = bytes([0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0])
            pc._write_png(path, 2, 2, pixels)
            self.assertTrue(path.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
            self.assertEqual(struct.unpack('>II', path.read_bytes()[16:24]), (2, 2))

    def test_two_color_terminal_pixels_are_valid_not_blank(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'two-color-fixture.png'
            pc._write_png(path, 2, 1, bytes([0, 0, 0, 0, 255, 255, 255, 0]))
            self.assertTrue(path.is_file())


if __name__ == '__main__':
    unittest.main()
