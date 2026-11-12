"""实验三命令行助手：准备、检查、配置采集、证据归档与离线分析。"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import collect_switches as collector
from lab_spec import STAGES, TOPOLOGY_FILES, expected_pc1
from prepare_topology import generate_bundle, read_topology, validate_topology

ROOT = Path(__file__).resolve().parents[1]


def timestamp():
    return datetime.now(timezone(timedelta(hours=8))).strftime('%Y%m%dT%H%M%S.%f%z')


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def check():
    """静态检查；不启动设备、不发送配置。端口探测只判断是否已监听。"""
    bundle = collector.latest_bundle()
    results = {}
    for experiment in ('part1', 'part2'):
        manifest = json.loads((bundle/'manifest.json').read_text(encoding='utf-8'))
        results[experiment] = validate_topology(read_topology(bundle/TOPOLOGY_FILES[experiment]), experiment, manifest)
    ports = {}
    for port in (2100, 2200, 2201, 2202):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                ports[str(port)] = 'listening; identity not yet verified'
        except OSError:
            ports[str(port)] = 'not listening'
    info = {'kind': '准备检查，非通信实测', 'checked_at': timestamp(), 'bundle': str(bundle),
            'topology_validation': results, 'console_ports': ports, 'python_version': sys.version,
            'ensp_installed': Path('C:/Program Files/Huawei/eNSP/eNSP_Client.exe').exists(),
            'tshark_installed': any(Path(p).exists() for p in ('C:/Program Files/Wireshark/tshark.exe',
                                     'C:/Program Files (x86)/Wireshark/tshark.exe')),
            'port_decision_confirmed': False}
    decision = ROOT/'local'/'state'/'decisions.json'
    if decision.exists():
        info['port_decision_confirmed'] = json.loads(decision.read_text(encoding='utf-8')).get('port_range', {}).get('status') == 'confirmed'
    path = ROOT/'local'/'checks'/timestamp()/'check.json'
    save_json(path, info)
    print(f'两套工程结构校验通过，PC 地址已预填。准备检查记录：{path}')
    print(f'打开同一批次的工程：{bundle}')
    print('接口名称：'+('已记录确认' if info['port_decision_confirmed'] else '待老师确认；VLAN2 配置执行保持锁定'))
    print('Console：'+('、'.join(f'{p} {"已监听" if v.startswith("listening") else "未启动"}' for p, v in ports.items())))
    return info


def confirm_ports(note):
    """记录用户确认的接口名称，保留来源与依据；不编辑课程原件。"""
    if not note.strip():
        raise ValueError('请用 --note 填写确认 Ethernet 端口的依据')
    path = ROOT/'local'/'state'/'decisions.json'
    info = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    info['port_range'] = {'status': 'confirmed', 'interface': 'Ethernet', 'note': note,
                          'recorded_at': datetime.now(timezone(timedelta(hours=8))).isoformat(), 'source': 'user'}
    history = ROOT/'local'/'state'/'decision-history'/f'{timestamp()}.json'
    save_json(history, info)
    save_json(path, info)
    print('已记录 Ethernet 端口确认。原 PPT 和 Word 保持原样。')


def import_evidence(stage, kind, source, label):
    source = Path(source).resolve()
    if not source.is_file() or source.stat().st_size == 0:
        raise ValueError('证据文件不存在或为空，请先保存实际文件')
    allowed = {'screenshot': {'.png', '.jpg', '.jpeg', '.bmp'},
               'capture': {'.pcap', '.pcapng', '.cap'}, 'ping': {'.txt', '.log'}}
    if source.suffix.lower() not in allowed[kind]:
        raise ValueError('文件扩展名与证据类型不符')
    destination = ROOT/'local'/'evidence'/stage/(timestamp()+'-'+kind)
    destination.mkdir(parents=True, exist_ok=False)
    copied = destination/('original'+source.suffix.lower())
    shutil.copyfile(source, copied)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if hashlib.sha256(copied.read_bytes()).hexdigest() != digest:
        raise ValueError('归档副本哈希与来源不一致，请重新保存文件后归档')
    save_json(destination/'manifest.json', {'kind': kind, 'stage': stage, 'label': label,
        'source': str(source), 'stored_file': copied.name, 'sha256': digest,
        'collected_at': timestamp(), 'review_status': '已归档，内容待核对'})
    print(f'证据已归档并校验哈希：{destination}')
    return destination


def status():
    print('以下是理论预期；配置回读、证据文件及通信结果分别记录。')
    for stage, info in STAGES.items():
        pings = ', '.join(f'PC1→{host} {"通" if ok else "不通"}' for host, ok in expected_pc1(stage).items())
        records = list((ROOT/'local'/'records').glob('*-'+stage+'/manifest.json'))
        evidence = list((ROOT/'local'/'evidence'/stage).glob('*/manifest.json'))
        print(f'{stage}: {pings}；Console记录{len(records)}份，证据归档{len(evidence)}份')
    print('逐项要求和待办见 exp3/local/操作清单.md；归档数量不等于内容验收完成。')


def menu():
    print('本助手用于实验3的两个部分。先在 eNSP 打开同一批次的对应工程并启动设备。')
    try:
        print('当前工程批次：', collector.latest_bundle())
    except ValueError as exc:
        print(exc)
    while True:
        print('\n实验三助手\n1 检查现有工程\n2 查看阶段和记录\n3 配置并回读\n4 只读采集\n5 分析已保存抓包\n6 归档证据\n0 退出')
        choice = input('选择：').strip()
        if choice == '0':
            return
        try:
            if choice == '1':
                check()
            elif choice == '2':
                status()
            elif choice in ('3', '4'):
                stages = list(STAGES)
                for i, stage in enumerate(stages, 1):
                    print(f'{i} {stage}：{STAGES[stage]["description"]}')
                value = int(input('阶段序号：'))
                if not 1 <= value <= len(stages):
                    raise ValueError('阶段序号超出范围')
                stage = stages[value-1]
                ports = [2100] if stage.startswith('part1') else [2200, 2201, 2202]
                destination = collector.collect(stage, ports, apply=choice == '3')
                print(f'配置回读与查询记录：{destination}')
                print('下一步按操作清单完成 PC ping、抓包和截图；本步骤只核对交换机配置。')
            elif choice == '5':
                path = input('已保存抓包的完整路径：').strip().strip('"')
                subprocess.run([sys.executable, str(ROOT/'scripts'/'analyze_capture.py'), path], check=True)
            elif choice == '6':
                stage = input('阶段名称（如 part2-routing）：').strip()
                if stage not in STAGES:
                    raise ValueError('阶段名称不正确')
                kind = input('类型 screenshot/capture/ping：').strip()
                if kind not in ('screenshot', 'capture', 'ping'):
                    raise ValueError('证据类型不正确')
                source = input('已保存文件的完整路径：').strip().strip('"')
                label = input('说明（如 PC1到PC3 或 S1-S2 同网段）：').strip()
                import_evidence(stage, kind, source, label)
        except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f'已停止当前步骤：{exc}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('prepare', 'check', 'status', 'menu'):
        sub.add_parser(action)
    confirmation = sub.add_parser('confirm-ports', help='记录已确认的 Ethernet 接口名称及依据')
    confirmation.add_argument('--note', required=True)
    evidence = sub.add_parser('evidence')
    evidence.add_argument('--stage', choices=STAGES, required=True)
    evidence.add_argument('--kind', choices=('screenshot', 'capture', 'ping'), required=True)
    evidence.add_argument('--file', type=Path, required=True)
    evidence.add_argument('--label', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            print('新批次工程及配置：', *generate_bundle())
        elif args.action == 'check':
            check()
        elif args.action == 'status':
            status()
        elif args.action == 'menu':
            menu()
        elif args.action == 'confirm-ports':
            confirm_ports(args.note)
        elif args.action == 'evidence':
            import_evidence(args.stage, args.kind, args.file, args.label)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f'操作停止：{exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
