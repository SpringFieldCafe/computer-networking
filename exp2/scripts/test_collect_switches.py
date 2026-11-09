"""使用模拟 Console 验证分页、错误处理和实验配置/采集顺序。"""
import contextlib
import io
import socket
import tempfile
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch

import collect_switches as collector
import prepare_topology


class ScriptedConsole:
    def __init__(self, error_command=None, confirm_stp=True, ignore_aging=False):
        self.commands = []
        self.chunks = deque()
        self.prompt = b'<Huawei>'
        self.error_command = error_command
        self.confirm_stp = confirm_stp
        self.ignore_aging = ignore_aging
        self.waiting_confirmation = False
        self.confirmations = []
        self.aging = 300
        self.stp_disabled = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        command = data.decode('ascii').strip()
        if self.waiting_confirmation:
            if command != 'y':
                raise AssertionError('确认完成前发送了下一条配置命令')
            self.confirmations.append(command)
            self.waiting_confirmation = False
            self.stp_disabled = True
            self.chunks.append(b'y\r\nInfo: Succeeded.\r\n' + self.prompt)
            return
        if command:
            self.commands.append(command)
        body = b''
        if command == self.error_command:
            body = b'Error: Configuration rejected.\r\n'
        elif command == 'stp disable':
            if self.confirm_stp:
                self.waiting_confirmation = True
                self.chunks.append(data + b'Warning: The global STP state will be changed. Continue? [Y/N]')
                return
            self.stp_disabled = True
        elif command == 'mac-address aging-time 0' and not self.ignore_aging:
            self.aging = 0
        elif command == 'display mac-address aging-time':
            body = f'Aging time: {self.aging} seconds\r\n'.encode()
        elif command == collector.STP_QUERY and self.stp_disabled:
            body = b'stp disable\r\n'
        elif command.startswith('sysname '):
            self.prompt = ('[' + command.split()[1] + ']').encode()
        elif command == 'return':
            self.prompt = b'<' + self.prompt.strip(b'[]') + b'>'
        self.chunks.append(data + body + self.prompt)

    def recv(self, size):
        if self.chunks:
            return self.chunks.popleft()
        raise socket.timeout()


class PagedConsole:
    def __init__(self):
        self.chunks = deque([b'header\r\nentry-1\r\n\x1b[7m---- Mo', b're ----\x1b[0m'])
        self.pages = deque([b'\r\nentry-2\r\n---- More ----', b'\r\nentry-3\r\n<SW1>\x1b[K'])
        self.sent = []

    def recv(self, size):
        if self.chunks:
            return self.chunks.popleft()
        raise socket.timeout()

    def sendall(self, data):
        self.sent.append(data)
        if data == b' ' and self.pages:
            self.chunks.append(self.pages.popleft())


class ConsoleTests(unittest.TestCase):
    def test_console_prompt(self):
        sock = ScriptedConsole()
        sock.sendall(b'\r\n')
        self.assertIn('<Huawei>', collector.read_prompt(sock, timeout=0.1))

    def test_fragmented_telnet_negotiation(self):
        sock = PagedConsole()
        sock.chunks = deque([b'\xff', b'\xfb', b'\x01hello\r\n<SW1>'])
        result = collector.read_prompt(sock, timeout=0.1)
        self.assertIn('hello', result)
        self.assertEqual(sock.sent, [b'\xff\xfe\x01'])

    def test_continues_every_page(self):
        sock = PagedConsole()
        result = collector.read_prompt(sock, timeout=0.1)
        self.assertEqual(sock.sent, [b' ', b' '])
        for entry in ['entry-1', 'entry-2', 'entry-3']:
            self.assertIn(entry, result)

    def test_disconnect_keeps_partial_output(self):
        sock = PagedConsole()
        sock.chunks = deque([b'partial output', b''])
        with self.assertRaises(collector.ConsoleReadError) as caught:
            collector.read_prompt(sock, timeout=0.1)
        self.assertEqual(caught.exception.output, 'partial output')

    def test_prepare_keeps_assignment_commands(self):
        consoles = [ScriptedConsole() for _ in range(3)]
        with tempfile.TemporaryDirectory(prefix='cn-console-test-') as td:
            with patch.object(collector.socket, 'create_connection', side_effect=consoles), contextlib.redirect_stdout(io.StringIO()):
                collector.collect([2000, 2001, 2002], 0, True, Path(td))
            for number, sock in enumerate(consoles, 1):
                self.assertEqual(sock.commands, ['undo terminal monitor', 'system-view',
                    f'sysname SW{number}', 'stp disable', 'mac-address aging-time 0',
                    'undo mac-address dynamic', 'return', 'display mac-address',
                    'display mac-address aging-time', collector.STP_QUERY])
                self.assertEqual(sock.confirmations, ['y'])
                self.assertTrue((Path(td)/'step-0'/f'SW{number}.txt').is_file())

    def test_step_collection_only_queries(self):
        consoles = [ScriptedConsole() for _ in range(3)]
        with tempfile.TemporaryDirectory(prefix='cn-console-test-') as td:
            with patch.object(collector.socket, 'create_connection', side_effect=consoles), contextlib.redirect_stdout(io.StringIO()):
                collector.collect([2000, 2001, 2002], 4, False, Path(td))
            for sock in consoles:
                self.assertEqual(sock.commands, ['display mac-address', 'display mac-address aging-time'])

    def test_real_command_error_stops_and_saves(self):
        sock = ScriptedConsole(error_command='stp disable')
        with tempfile.TemporaryDirectory(prefix='cn-console-test-') as td:
            with patch.object(collector.socket, 'create_connection', return_value=sock) as connect:
                with self.assertRaisesRegex(RuntimeError, 'SW1.*stp disable.*Configuration rejected'):
                    collector.collect([2000, 2001, 2002], 0, True, Path(td))
            connect.assert_called_once()
            self.assertNotIn('undo mac-address dynamic', sock.commands)
            self.assertIn('Error: Configuration rejected.', (Path(td)/'step-0/SW1.txt').read_text(encoding='utf8'))

    def test_prepare_when_stp_already_disabled(self):
        sock = ScriptedConsole(confirm_stp=False)
        with tempfile.TemporaryDirectory(prefix='cn-console-test-') as td:
            with patch.object(collector.socket, 'create_connection', return_value=sock), contextlib.redirect_stdout(io.StringIO()):
                collector.collect([2000], 0, True, Path(td))
        self.assertEqual(sock.confirmations, [])

    def test_unexpected_confirmation_stops(self):
        sock = PagedConsole()
        sock.chunks = deque([b'Delete something? [Y/N]'])
        with self.assertRaisesRegex(collector.ConsoleReadError, '交互确认'):
            collector.read_prompt(sock, timeout=0.1, confirm_stp_disable=True)
        self.assertEqual(sock.sent, [])

    def test_readback_detects_configuration_not_applied(self):
        sock = ScriptedConsole(ignore_aging=True)
        with tempfile.TemporaryDirectory(prefix='cn-console-test-') as td:
            with patch.object(collector.socket, 'create_connection', return_value=sock):
                with self.assertRaisesRegex(RuntimeError, '老化时间回读'):
                    collector.collect([2000], 0, True, Path(td))

    def test_generated_manual_configs_use_console_commands(self):
        with tempfile.TemporaryDirectory(prefix='cn-topology-test-') as td:
            with patch.object(prepare_topology, 'ROOT', Path(td)), contextlib.redirect_stdout(io.StringIO()):
                prepare_topology.build()
            for number in range(1, 4):
                text = (Path(td)/'config'/f'SW{number}.txt').read_text()
                self.assertEqual(text.splitlines(), collector.commands_for(f'SW{number}', True))
                self.assertNotIn('screen-length', text)

    def test_prepare_is_limited_to_initial_step(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                collector.main(['--prepare', '--step', '3'])
        self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
