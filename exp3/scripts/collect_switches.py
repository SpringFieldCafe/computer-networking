"""实验三分阶段配置与只读采集。只连接本机 Console，原始输出保存在 local。"""
import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('part1-default', 'part1-vlan2', 'part2-access', 'part2-l2-optional', 'part2-routing')
QUERIES = ('display current-configuration', 'display vlan', 'display port vlan',
           'display interface brief', 'display ip interface brief',
           'display mac-address', 'display arp', 'display ip routing-table')
ANSI = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
PROMPT = re.compile(rb'(?:<[^<>\r\n]+>|\[[^\[\]\r\n]+\])\s*$')
ERROR = re.compile(r'(?im)^\s*(?:Error\s*:|Failure\s*:|Unrecognized command|Wrong parameter|Incomplete command)')


class ConsoleError(RuntimeError):
    def __init__(self, message, partial=''):
        super().__init__(message)
        self.partial = partial


def latest_bundle():
    bundles = sorted((ROOT/'local'/'topology').glob('*/manifest.json'))
    if not bundles:
        raise ValueError('请先运行 assistant.py prepare 生成独立工程')
    return bundles[-1].parent


def runtime_guard(stage, ports, bundle=None):
    """核对工程、缓存资源及 Console；缓存 ID 不等于活进程身份。只读。"""
    from prepare_topology import read_topology, validate_topology
    from lab_spec import TOPOLOGY_FILES
    experiment = 'part1' if stage.startswith('part1') else 'part2'
    selected = Path(bundle).resolve() if bundle else latest_bundle()
    if not selected.is_relative_to((ROOT/'local').resolve()):
        raise ValueError('运行工程必须位于 exp3/local')
    manifest = json.loads((selected/'manifest.json').read_text(encoding='utf-8'))
    topo_path = selected/TOPOLOGY_FILES[experiment]
    expected_hash = manifest.get('files_sha256', {}).get(topo_path.name)
    actual_hash = hashlib.sha256(topo_path.read_bytes()).hexdigest()
    if not expected_hash or expected_hash != actual_hash:
        raise ValueError('拓扑哈希与选定批次 manifest 不一致，请核对工程或重新准备批次')
    topo = read_topology(topo_path)
    validate_topology(topo, experiment, manifest)
    devices = sorted((d for d in topo.findall('./devices/dev') if d.get('model') == 'S3700'), key=lambda d: d.get('name'))
    if ports != [int(d.get('com_port')) for d in devices]:
        raise ValueError('Console 端口与选定工程不一致；请先核对工程，不连接旧实验')
    if not os.environ.get('LOCALAPPDATA'):
        raise ValueError('缺少 LOCALAPPDATA，无法定位 eNSP 运行资源')
    workspace = Path(os.environ['LOCALAPPDATA'])/'eNSP'/'VBoxServer'/'workspaces'
    for dev in devices:
        cfg = workspace/dev.get('id')/'slot17'/'hardcfg.tcl'
        ids = re.findall(r'(?im)^\s*SetDeviceID\s+(\S+)', cfg.read_text(encoding='utf-8', errors='replace')) if cfg.is_file() else []
        ids = [value.strip('{}"').upper() for value in ids]
        if ids != [dev.get('id').upper()]:
            raise ValueError(f'{dev.get("name")} 的新工程运行资源尚未就绪，请手动打开选定工程并启动设备')
    if sys.platform != 'win32':
        raise ValueError('运行设备检查需要 Windows eNSP；其他平台可运行准备与测试')
    numbers = ','.join(str(int(p)) for p in ports)
    ps = (f'$ErrorActionPreference="Stop"; @(Get-NetTCPConnection -State Listen -LocalPort {numbers} | '
          'ForEach-Object { [PSCustomObject]@{Port=$_.LocalPort; PID=$_.OwningProcess; '
          'Name=(Get-Process -Id $_.OwningProcess).ProcessName} }) | ConvertTo-Json -Compress')
    completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', ps],
                               capture_output=True, timeout=20, check=False)
    if completed.returncode or not completed.stdout.strip():
        raise ValueError('Console 尚未监听或进程查询失败；请检查新工程是否启动')
    rows = json.loads(completed.stdout.decode('utf-8-sig'))
    rows = [rows] if isinstance(rows, dict) else rows
    if (not isinstance(rows, list) or not rows or
            any(not isinstance(r, dict) or not {'Port', 'PID', 'Name'}.issubset(r) or
                not isinstance(r['Port'], int) or not isinstance(r['Name'], str) for r in rows)):
        raise ValueError('Console 进程查询结果不完整，停止连接')
    if ({r['Port'] for r in rows} != set(ports) or
            len({r['PID'] for r in rows}) != 1 or
            any(not isinstance(r['PID'], int) or r['PID'] <= 0 or
                r['Name'].lower().removesuffix('.exe') != 'ensp_client' for r in rows)):
        raise ValueError('Console 进程归属与 eNSP 不符，停止连接')
    return {'bundle': str(selected), 'device_ids': {d.get('name'): d.get('id') for d in devices},
            'topology_sha256': actual_hash, 'manifest_ids_verified': True,
            'console_owners': rows, 'same_console_process_verified': True,
            'live_device_id_binding_verified': False,
            'runtime_identity_status': '运行待核：hardcfg 为缓存资源；活进程到设备 ID 的关联须现场核对',
            'binding_note': '本机现存 hardcfg 样本未提供可核实的 Console TCP 端口绑定格式'}


def read_prompt(sock, timeout=20):
    """处理拆包的 Telnet 协商、分页和提示符；遇到确认问题停止。"""
    end = time.monotonic() + timeout
    output, pending = bytearray(), bytearray()
    pages_answered = 0
    while time.monotonic() < end:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            visible = ANSI.sub(b'', output).rstrip(b'\x00')
            if PROMPT.search(visible):
                return visible.decode('utf-8', errors='replace')
            continue
        except OSError as exc:
            raise ConsoleError(f'Console 读取失败：{exc}', output.decode('utf-8', errors='replace')) from exc
        if not data:
            raise ConsoleError('Console 已关闭', output.decode('utf-8', errors='replace'))
        pending.extend(data)
        while pending:
            if pending[0] != 255:
                output.append(pending.pop(0))
            elif len(pending) < 2:
                break
            elif pending[1] == 255:
                output.append(255)
                del pending[:2]
            elif pending[1] in (251, 252, 253, 254):
                if len(pending) < 3:
                    break
                if pending[1] in (251, 253):
                    sock.sendall(bytes((255, 254 if pending[1] == 251 else 252, pending[2])))
                del pending[:3]
            elif pending[1] == 250:
                stop = pending.find(b'\xff\xf0', 2)
                if stop < 0:
                    break
                del pending[:stop + 2]
            else:
                del pending[:2]
        visible = ANSI.sub(b'', output)
        if re.search(rb'(?i)(?:\[\s*Y\s*/\s*N\s*\]|password\s*:|username\s*:)\s*[:]?\s*$', visible):
            raise ConsoleError('设备要求交互确认或认证，请人工核对', visible.decode('utf-8', errors='replace'))
        pages = len(re.findall(rb'-{2,}\s*More\s*-{2,}', visible, re.I))
        for _ in range(pages_answered, pages):
            sock.sendall(b' ')
        pages_answered = pages
    raise ConsoleError('等待设备提示符超时', output.decode('utf-8', errors='replace'))


def commands_for(stage, name):
    if stage == 'part1-default':
        # PPT 的配置前观察保持设备默认状态，只回读，不把 hybrid 改成 access。
        return []
    commands = ['undo terminal monitor', 'system-view', f'sysname {name}']
    if stage == 'part1-vlan2':
        commands += ['vlan 2', 'quit', 'port-group g2',
                     'group-member Ethernet 0/0/13 to Ethernet 0/0/22',
                     'port link-type access', 'port default vlan 2', 'quit']
    elif name in ('S2', 'S3'):
        commands += ['vlan batch 100 200', 'interface Ethernet0/0/3',
                     'port link-type trunk', 'port trunk allow-pass vlan 100 200', 'quit']
        for port, vlan in ((1, 100), (2, 200)):
            commands += [f'interface Ethernet0/0/{port}', 'port link-type access',
                         f'port default vlan {vlan}', 'quit']
    elif stage in ('part2-l2-optional', 'part2-routing'):
        commands += ['vlan batch 100 200']
        for port in (1, 2):
            commands += [f'interface Ethernet0/0/{port}', 'port link-type trunk',
                         'port trunk allow-pass vlan 100 200', 'quit']
        if stage == 'part2-routing':
            for vlan in (100, 200):
                commands += [f'interface Vlanif {vlan}',
                             f'ip address 192.168.{vlan}.254 255.255.255.0', 'quit']
    else:
        # 课件第16页的 S1 保持默认，只查询。
        return []
    return commands + ['return']


def interface_blocks(text):
    blocks = {}
    current = None
    for line in text.splitlines():
        match = re.fullmatch(r'interface\s+(\S+)', line.strip(), re.I)
        if match:
            current = match.group(1).lower()
            blocks[current] = []
        elif line.strip() in ('#', 'return'):
            current = None
        elif current:
            blocks[current].append(line.strip().lower())
    return blocks


def vlan_set(line):
    tokens = line.split('vlan', 1)[-1].split()
    if 'all' in tokens:
        return set(range(1, 4095))
    values = set()
    for i, token in enumerate(tokens):
        if token.isdigit():
            if i > 0 and tokens[i-1] == 'to' and i > 1 and tokens[i-2].isdigit():
                values.update(range(int(tokens[i-2]), int(token)+1))
            else:
                values.add(int(token))
    return values


def required_ports(stage, name):
    if stage.startswith('part1'):
        return tuple(range(1, 23))
    return (1, 2) if name == 'S1' else (1, 2, 3)


def verify_config(stage, name, config, ip_brief='', vlan_output=None):
    """核对设备回读的生效配置，默认 PVID=1；运行状态另列，便于排障。"""
    blocks = interface_blocks(config)
    issues, warnings = [], []
    if not blocks:
        issues.append('当前配置回读为空或未包含接口段，配置尚未验证')
    for port in required_ports(stage, name):
        if f'ethernet0/0/{port}' not in blocks:
            issues.append(f'缺少 Ethernet0/0/{port} 配置回读')
    declared_vlans = {1}
    for line in config.lower().splitlines():
        if re.match(r'^vlan(?:\s+batch)?\s+\d', line):
            declared_vlans.update(vlan_set(line.replace('batch ', '')))
    expected_vlans = ({2} if stage == 'part1-vlan2' else
                      {100, 200} if stage.startswith('part2') and not (stage == 'part2-access' and name == 'S1') else {1})
    if not expected_vlans.issubset(declared_vlans):
        issues.append('当前配置缺少本阶段 VLAN 定义：'+str(sorted(expected_vlans-declared_vlans)))
    if vlan_output is not None:
        observed = {int(x) for x in re.findall(r'(?m)^\s*(\d+)\s+(?:common|super|sub)\b', vlan_output, re.I)}
        if not expected_vlans.issubset(observed):
            issues.append('display vlan 未回读到本阶段全部 VLAN，生效状态待核')

    def access(port, vlan):
        lines = blocks.get(f'ethernet0/0/{port}', [])
        pvid = next((int(x.split()[-1]) for x in lines if x.startswith('port default vlan ')), 1)
        hybrid_pvid = next((int(x.split()[-1]) for x in lines if x.startswith('port hybrid pvid vlan ')), 1)
        mode = next((x.split()[-1] for x in lines if x.startswith('port link-type ')), 'hybrid')
        if pvid != vlan:
            issues.append(f'Ethernet0/0/{port} PVID 应为 {vlan}')
        if vlan != 1 and mode != 'access':
            issues.append(f'Ethernet0/0/{port} 应为 access')
        if vlan == 1 and (mode not in ('access', 'hybrid') or hybrid_pvid != 1 or
                any(x.startswith(('port trunk ', 'port hybrid tagged vlan ')) or
                    (x.startswith('port hybrid untagged vlan ') and vlan_set(x) != {1}) for x in lines)):
            issues.append(f'Ethernet0/0/{port} 应保持默认 VLAN1 转发状态，发现链路模式或 VLAN 残留')

    def trunk(port):
        lines = blocks.get(f'ethernet0/0/{port}', [])
        allowed = {1}
        for line in lines:
            if line.startswith('port trunk allow-pass vlan '):
                allowed.update(vlan_set(line))
        if 'port link-type trunk' not in lines or not {100, 200}.issubset(allowed):
            issues.append(f'Ethernet0/0/{port} 应为允许 VLAN100/200 的 trunk')
        if any(x.startswith('port trunk pvid vlan ') and x.split()[-1] != '1' for x in lines):
            issues.append(f'Ethernet0/0/{port} trunk PVID 应保持 1')

    if stage.startswith('part1'):
        for port in range(1, 23):
            access(port, 2 if stage == 'part1-vlan2' and port >= 13 else 1)
        if any(k.startswith('vlanif') and k != 'vlanif1' for k in blocks):
            issues.append('实验内容1应使用独立工程，发现额外 Vlanif')
    elif name in ('S2', 'S3'):
        access(1, 100)
        access(2, 200)
        trunk(3)
    elif stage == 'part2-access':
        if any(k in blocks for k in ('vlanif100', 'vlanif200')):
            issues.append('课件第16页阶段 S1 尚未配置 Vlanif100/200，请使用新工程')
        for port in (1, 2):
            access(port, 1)
    else:
        trunk(1)
        trunk(2)
        for vlan in (100, 200):
            lines = blocks.get(f'vlanif{vlan}', [])
            if stage == 'part2-routing':
                if f'ip address 192.168.{vlan}.254 255.255.255.0' not in lines:
                    issues.append(f'Vlanif{vlan} 网关地址不匹配')
                row = next((x for x in ip_brief.splitlines() if re.match(fr'^\s*Vlanif\s*{vlan}\s', x, re.I)), '')
                if len(re.findall(r'\bup\b', row, re.I)) < 2:
                    warnings.append(f'请检查 Vlanif{vlan} 的物理状态与协议状态是否均为 up')
            elif f'vlanif{vlan}' in blocks:
                issues.append('可选二层验证阶段应先于三层路由阶段运行')
    return {'configuration_ok': not issues, 'issues': issues, 'operational_warnings': warnings}


def collect(stage, ports, apply=False, output_root=None, bundle=None):
    if stage not in STAGES:
        raise ValueError('阶段名称不正确')
    if apply and stage == 'part1-vlan2':
        decision_path = ROOT/'local'/'state'/'decisions.json'
        decision = json.loads(decision_path.read_text(encoding='utf-8')) if decision_path.exists() else {}
        port_decision = decision.get('port_range', {})
        if port_decision.get('status') != 'confirmed' or port_decision.get('interface') != 'Ethernet':
            raise ValueError('尚未记录用户确认的 Ethernet 接口选择；请先用 assistant.py confirm-ports 记录依据，再执行本阶段')
    names = ['S1'] if stage.startswith('part1') else ['S1', 'S2', 'S3']
    if len(ports) != len(names) or len(set(ports)) != len(ports) or any(not 1024 <= x <= 65535 for x in ports):
        raise ValueError('Console 端口数量、范围或唯一性不正确')
    base = (output_root or ROOT/'local'/'records').resolve()
    if not base.is_relative_to((ROOT/'local').resolve()):
        raise ValueError('原始记录必须保存在 exp3/local 内')
    now = datetime.now(timezone(timedelta(hours=8)))
    destination = base/(now.strftime('%Y%m%dT%H%M%S.%f%z')+'-'+stage)
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {'kind': 'eNSP Console 实际输出', 'stage': stage, 'started_at': now.isoformat(),
                'apply': apply, 'ports': dict(zip(names, ports)), 'status': 'running', 'devices': {},
                'python_version': sys.version, 'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'completion_scope': '交换机配置回读；ping、截图与抓包另行验收'}
    active = None
    transcripts = {name: [] for name in names}

    def execute(sock, name, command):
        transcripts[name].append(f'COMMAND: {command}\n')
        try:
            sock.sendall(command.encode('ascii') + b'\r\n')
            response = read_prompt(sock)
        except ConsoleError as exc:
            transcripts[name][-1] += exc.partial
            raise
        transcripts[name][-1] += response
        if ERROR.search(response):
            raise ConsoleError(f'{name} 命令失败：{command}')
        return response

    try:
        manifest['runtime_guard'] = runtime_guard(stage, ports, bundle)
        # 先连齐所有设备并只读识别，再下发配置，减少部分设备配置后才发现端口错的情况。
        with ExitStack() as stack:
            sockets = {}
            for name, port in zip(names, ports):
                active = name
                sock = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=3))
                sockets[name] = sock
                sock.settimeout(0.3)
                sock.sendall(b'\r\n')
                try:
                    banner = read_prompt(sock)
                except ConsoleError as exc:
                    transcripts[name].append(exc.partial)
                    raise
                transcripts[name].append(banner)
                if apply and banner.rstrip().endswith(']'):
                    execute(sock, name, 'return')
                version = execute(sock, name, 'display version')
                if 'VRP' not in version.upper():
                    raise ConsoleError(f'{name} 端口未返回 VRP 版本，请检查 Console 映射')
                initial = execute(sock, name, 'display current-configuration')
                initial_blocks = interface_blocks(initial)
                if any(f'ethernet0/0/{p}' not in initial_blocks for p in required_ports(stage, name)):
                    raise ConsoleError(f'{name} 初始配置回读缺少接口，停止下发')
                if apply and name == 'S1' and stage in ('part2-access', 'part2-l2-optional'):
                    if re.search(r'(?im)^interface\s+Vlanif\s*(100|200)\s*$', initial):
                        raise ConsoleError('S1 已有三层配置，请从独立新工程开始，保留旧实验记录')
                    if stage == 'part2-access' and not verify_config(stage, name, initial)['configuration_ok']:
                        raise ConsoleError('S1 不是默认 VLAN1 基线，停止下发；请打开独立新工程')
            for name, sock in sockets.items():
                active = name
                if apply:
                    for command in commands_for(stage, name):
                        execute(sock, name, command)
                responses = {q: execute(sock, name, q) for q in QUERIES}
                result = verify_config(stage, name, responses[QUERIES[0]], responses[QUERIES[4]], responses[QUERIES[1]])
                manifest['devices'][name] = result
                if not result['configuration_ok']:
                    raise ConsoleError(f'{name} 回读配置与当前阶段不一致，请查看 manifest.json')
            manifest['status'] = 'configuration_verified'
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        manifest.update(status='failed', active_device=active, error=str(exc))
        raise ConsoleError(f'采集停止，诊断保存在 {destination}') from exc
    except KeyboardInterrupt:
        manifest.update(status='interrupted', active_device=active, error='用户中断采集')
        raise
    finally:
        for name, lines in transcripts.items():
            path = destination/f'{name}.txt'
            path.write_text('\n\n'.join(lines), encoding='utf-8')
        manifest['completed_at'] = datetime.now(timezone(timedelta(hours=8))).isoformat()
        manifest['files'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.glob('*.txt')}
        (destination/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--apply', action='store_true', help='下发本阶段配置并回读；省略则只查询')
    parser.add_argument('--ports', type=int, nargs='+', help='按 S1 或 S1 S2 S3 顺序指定端口')
    parser.add_argument('--bundle', type=Path, help='准备批次目录；默认最近生成批次。必须打开同一批次的工程')
    args = parser.parse_args(argv)
    ports = args.ports or ([2100] if args.stage.startswith('part1') else [2200, 2201, 2202])
    try:
        destination = collect(args.stage, ports, args.apply, bundle=args.bundle)
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f'配置回读已核对，原始输出：{destination}。运行工程身份关联待现场核对；ping、抓包与截图按操作清单采集。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
