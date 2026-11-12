"""连接本机 eNSP 的三个 Console 端口，配置实验或保存逐步 MAC 表。"""
import argparse
import re
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANSI_ESCAPE = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
MORE_PROMPT = re.compile(rb'-{2,}[ \t]*More[ \t]*-{2,}', re.I)
COMMAND_PROMPT = re.compile(rb'(?:<[^<>\r\n]+>|\[[^\[\]\r\n]+\])\s*$')
CONFIRMATION_PROMPT = re.compile(rb'\[[ \t]*Y[ \t]*/[ \t]*N[ \t]*\][ \t:]*$', re.I)
STP_CONFIRMATION = b'The global STP state will be changed. Continue?'
STP_QUERY = 'display current-configuration | include ^stp'


class ConsoleReadError(RuntimeError):
    def __init__(self, message, output):
        super().__init__(message)
        self.output = output.decode('utf8', errors='replace')


def commands_for(name, prepare):
    commands = []
    if prepare:
        commands.extend(['undo terminal monitor', 'system-view', f'sysname {name}',
                         'stp disable', 'mac-address aging-time 0',
                         'undo mac-address dynamic', 'return'])
    commands.extend(['display mac-address', 'display mac-address aging-time'])
    if prepare:
        commands.append(STP_QUERY)
    return commands


def read_prompt(sock, timeout=20, confirm_stp_disable=False, progress=None):
    end, output, pending = time.monotonic() + timeout, bytearray(), bytearray()
    pages_answered = 0
    confirmation_answered = False
    while time.monotonic() < end:
        if progress:
            progress(f'等待命令提示符：已接收 {len(output)} 字节，超时剩余 {max(0, int(end-time.monotonic()))} 秒')
        try:
            data = sock.recv(65536)
        except socket.timeout:
            visible = ANSI_ESCAPE.sub(b'', output).rstrip(b'\x00')
            if not CONFIRMATION_PROMPT.search(visible) and COMMAND_PROMPT.search(visible):
                return output.decode('utf8', errors='replace')
            continue
        if not data:
            raise ConsoleReadError('Console 连接已关闭', output)
        pending.extend(data)
        while pending:
            if pending[0] != 255:
                output.append(pending.pop(0))
                continue
            if len(pending) < 2:
                break
            op = pending[1]
            if op == 255:
                output.append(255)
                del pending[:2]
            elif op in (251, 252, 253, 254):
                if len(pending) < 3:
                    break
                if op in (251, 253):
                    sock.sendall(bytes((255, 254 if op == 251 else 252, pending[2])))
                del pending[:3]
            elif op == 250:
                stop = pending.find(b'\xff\xf0', 2)
                if stop < 0:
                    break
                del pending[:stop + 2]
            else:
                del pending[:2]
        # Console 保留设备原有的分页设置，遇到 More 提示时发送空格续页。
        # 按已回答的提示个数计数，兼容拆成多段到达的分页提示。
        visible = ANSI_ESCAPE.sub(b'', output)
        if CONFIRMATION_PROMPT.search(visible):
            if not confirm_stp_disable or STP_CONFIRMATION not in visible:
                raise ConsoleReadError('设备请求交互确认，请核对 Console 中的问题后继续', output)
            if not confirmation_answered:
                sock.sendall(b'y\r\n')
                confirmation_answered = True
        pages = len(MORE_PROMPT.findall(visible))
        for _ in range(pages_answered, pages):
            sock.sendall(b' ')
        pages_answered = pages
    raise ConsoleReadError('等待设备命令提示符超时，请核对设备已启动并进入命令行', output)


def verify_prepared(responses):
    if not re.search(r'Aging time:\s*0\s+seconds', responses['display mac-address aging-time'], re.I):
        raise RuntimeError('老化时间回读结果应为 0 seconds，请检查配置是否生效')
    if not re.search(r'^\s*stp\s+disable\s*$', responses[STP_QUERY], re.M):
        raise RuntimeError('STP 配置回读结果缺少 stp disable，请检查交互确认是否完成')
    if re.search(r'(?i)\b(?:[0-9a-f]{4}-){2}[0-9a-f]{4}\b', responses['display mac-address']):
        raise RuntimeError('初始 MAC 表仍有表项，请检查 Client 发包及背景流量后重新清表')


def collect(ports, step, prepare, output=None, progress=None):
    destination = (output if output is not None else ROOT/'local'/'records')/f'step-{step}'
    destination.mkdir(parents=True, exist_ok=True)
    done = 0
    total = sum(len(commands_for(f'SW{n}', prepare)) for n in range(1, len(ports)+1))
    for number, port in enumerate(ports, 1):
        name = f'SW{number}'
        transcript = []
        responses = {}
        command = '连接 Console'
        def waiting(detail):
            if progress:
                progress(f'{name} / {command} / {detail}', done, total)
        try:
            waiting(f'连接本机 Console {port}（最多3秒）')
            with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
                sock.settimeout(0.5)
                sock.sendall(b'\r\n')
                transcript.append(read_prompt(sock, progress=waiting))
                for command in commands_for(name, prepare):
                    waiting('正在下发命令')
                    sock.sendall(command.encode('ascii') + b'\r\n')
                    response = read_prompt(sock, confirm_stp_disable=prepare and command == 'stp disable', progress=waiting)
                    transcript.append(response)
                    responses[command] = response
                    error = re.search(r'(?:Error:[^\r\n]*|Unrecognized command[^\r\n]*|Wrong parameter[^\r\n]*|Incomplete command[^\r\n]*)', response)
                    if error:
                        raise RuntimeError(error.group(0))
                    done += 1
                    waiting('命令已返回')
                if prepare:
                    command = '核对初始化结果'
                    verify_prepared(responses)
        except (OSError, RuntimeError) as exc:
            if isinstance(exc, ConsoleReadError):
                transcript.append(exc.output)
            raise RuntimeError(f'{name} 执行“{command}”失败：{exc}。诊断文件：{destination/name}.txt') from exc
        finally:
            (destination/f'{name}.txt').write_text('\n'.join(transcript), encoding='utf8')
        print(f'{name}：第 {step} 步记录已保存。')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ports', type=int, nargs=3, default=[2000, 2001, 2002])
    p.add_argument('--step', type=int, choices=range(6), required=True)
    p.add_argument('--prepare', action='store_true', help='在第0步配置设备并清空动态表')
    p.add_argument('--output', type=Path, default=ROOT/'local'/'records', help='原始记录的保存目录')
    args = p.parse_args(argv)
    if args.prepare and args.step != 0:
        p.error('--prepare 配合 --step 0 使用')
    try:
        collect(args.ports, args.step, args.prepare, args.output)
    except RuntimeError as exc:
        print(f'采集停止：{exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
