"""从一轮实测记录导出经过字段筛选、地址替换的公开副本；原文件只读。"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid
import xml.etree.ElementTree as E

SEQUENCE = [(1, 5), (2, 4), (3, 5), (4, 3), (5, 4)]
LINKS = [('Client1', 1, 'SW1', 1), ('Client2', 1, 'SW1', 3),
         ('SW1', 2, 'SW2', 1), ('Client3', 1, 'SW2', 3),
         ('SW2', 2, 'SW3', 1), ('Client4', 1, 'SW3', 3), ('Client5', 1, 'SW3', 2)]
MAC_PATTERN = re.compile(r'(?i)(?:[0-9a-f]{4}-){2}[0-9a-f]{4}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')


def compact(value):
    return re.sub(r'[^0-9a-f]', '', value.lower())


def write_text(path, text):
    # 固定 UTF-8/LF，避免不同系统的换行转换改变公开数据的 SHA-256。
    Path(path).write_bytes(text.encode('utf-8'))


def public_mac(name):
    return bytes([2, 0, 0, 2, 1 if name.startswith('SW') else 0, int(name[-1])])


def manifest_for(source):
    result = {'version': 1, 'project': '交换机自学习_简化版.topo',
              'ports': [2120, 2121, 2122], 'switches': {}, 'pcs': {},
              'sequence': [list(pair) for pair in SEQUENCE]}
    for group in ('switches', 'pcs'):
        for name in source[group]:
            row = {'id': str(uuid.uuid5(uuid.NAMESPACE_URL, 'https://example.invalid/exp2-public/' + name)).upper(),
                   'mac': public_mac(name).hex('-').upper()}
            row.update({'port': 2119 + int(name[-1])} if group == 'switches' else {'ip': f'192.0.2.{int(name[-1])}'})
            result[group][name] = row
    if set(result['pcs']) != {f'Client{i}' for i in range(1, 6)} or set(result['switches']) != {f'SW{i}' for i in range(1, 4)}:
        raise ValueError('需要三台交换机、五台 PC 的标准实验清单')
    return result


def scrub_console(text, original):
    mapping = {compact(v['mac']): public_mac(name) for group in ('switches', 'pcs') for name, v in original[group].items()}
    def replace(match):
        value = mapping.get(compact(match[0]))
        if value is None:
            raise ValueError('Console 中出现清单以外的 MAC，请先人工核查')
        raw = value.hex()
        return '-'.join(raw[i:i+4] for i in range(0, 12, 4))
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = MAC_PATTERN.sub(replace, text)
    if any(ord(c) < 32 and c not in '\n\t' for c in text):
        raise ValueError('Console 含有未处理的控制字符')
    if re.search(r'(?i)([a-z]:[\\/]|password\s*[:=]|cookie\s*:|authorization\s*:|[\w.+-]+@[\w.-]+\.[a-z]{2,})', text):
        raise ValueError('Console 中出现需人工核查的路径或认证字段')
    return '\n'.join(line.rstrip() for line in text.splitlines()) + '\n'


def read_pcap(path):
    data = path.read_bytes()
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000), b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
               b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000), b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}
    if len(data) < 24 or data[:4] not in formats:
        raise ValueError('需要完整的 PCAP 文件')
    endian, scale = formats[data[:4]]
    if struct.unpack_from(endian + 'I', data, 20)[0] != 1:
        raise ValueError('仅接受 Ethernet PCAP')
    offset, number = 24, 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError('PCAP 记录头不完整')
        sec, sub, size, wire = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        if sub >= scale or offset + size > len(data):
            raise ValueError('PCAP 记录不完整或时间字段异常')
        number += 1
        yield number, sec * 1_000_000_000 + sub * (1_000_000_000 // scale), data[offset:offset+size], wire
        offset += size


def udp_packet(packet, original):
    """只接收本题五次 UDP 的完整字段；其余协议不进入公开副本。"""
    if len(packet) < 42 or packet[12:14] != b'\x08\x00':
        return None
    mapping = {bytes.fromhex(compact(v['mac'])): int(name[-1]) for name, v in original['pcs'].items()}
    src, dst = mapping.get(packet[6:12]), mapping.get(packet[:6])
    if (src, dst) not in SEQUENCE:
        raise ValueError('IPv4 报文不属于本题五次发送')
    step = SEQUENCE.index((src, dst)) + 1
    ip = packet[14:]
    if ip[0] != 0x45 or ip[9] != 17 or struct.unpack_from('!H', ip, 2)[0] != 29 or struct.unpack_from('!H', ip, 6)[0] & 0xbfff:
        raise ValueError('IP 头部与本题预期不符，需人工核查')
    if ip[12:20] != bytes([192, 0, 2, src, 192, 0, 2, dst]):
        raise ValueError('IP 地址应为文档用地址')
    sp, dp, length, _ = struct.unpack_from('!HHHH', ip, 20)
    if (sp, dp, length, ip[28:29]) != (1, 1, 9, bytes([step])) or len(ip) != 29:
        raise ValueError('UDP 字段或附带数据超出已审查范围')
    rewritten = public_mac(f'Client{dst}') + public_mac(f'Client{src}') + packet[12:]
    return step, rewritten


def stp_packet(packet, original):
    """本轮只有固定长度 MSTP BPDU；未知协议、配置名或桥地址一律停止导出。"""
    known = {bytes.fromhex(compact(v['mac'])): public_mac(name) for name, v in original['switches'].items()}
    if (len(packet) != 119 or packet[:6] != bytes.fromhex('0180c2000000')
            or packet[12:21] != bytes.fromhex('006942420300000302')):
        raise ValueError('出现未审查的背景帧')
    for offset in (6, 24, 36, 112):
        if packet[offset:offset+6] not in known:
            raise ValueError('STP 中出现清单以外的桥地址')
    if packet[56:88] != packet[6:12].hex().encode() + bytes(20):
        raise ValueError('MST 配置名超出已审查范围')
    rewritten = packet
    for old, new in known.items():
        rewritten = rewritten.replace(old, new).replace(old.hex().encode(), new.hex().encode())
    return rewritten


def topology(source_path, original, public):
    raw = Path(source_path).read_bytes()
    text = raw.decode('utf-16' if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig')
    source = E.fromstring(re.sub(r'^\s*<\?xml[^>]*\?>', '', text))
    devices = source.findall('./devices/dev')
    name_by_id = {d.get('id'): d.get('name') for d in devices}
    topo = E.Element('topo', version='1.2.00.510')
    out = E.SubElement(topo, 'devices')
    for dev in devices:
        name = dev.get('name')
        switch = name in public['switches']
        row = public['switches' if switch else 'pcs'][name]
        attrs = {key: dev.get(key) for key in ('cx', 'cy', 'edit_left', 'edit_top')}
        if any(re.fullmatch(r'-?\d+(?:\.\d+)?', value or '') is None for value in attrs.values()):
            raise ValueError('工程坐标应为数值')
        settings = dev.get('settings', '')
        if switch:
            settings = ''
        else:
            values = re.findall(r'-(simpc_\w+)\s+(\S+)', settings)
            allowed = {'simpc_ip', 'simpc_mask', 'simpc_gateway', 'simpc_mac', 'simpc_mc_dstip',
                       'simpc_mc_dstmac', 'simpc_dns1', 'simpc_dns2', 'simpc_ipv6', 'simpc_prefix',
                       'simpc_gatewayv6', 'simpc_dhcp_state', 'simpc_dhcpv6_state', 'simpc_dns_auto_state',
                       'simpc_igmp_version', 'simpc_group_ip_start', 'simpc_src_ip_start', 'simpc_group_num',
                       'simpc_group_step', 'simpc_src_num', 'simpc_src_step', 'simpc_type'}
            if set(k for k, _ in values) - allowed:
                raise ValueError('工程含有未审查的 PC 参数')
            expected = {key: '0' for key in allowed}
            expected.update(simpc_ip=row['ip'], simpc_mask='255.255.255.0', simpc_prefix='128',
                            simpc_igmp_version='1', simpc_type='MODE_IS_INCLUDE', simpc_ipv6='::',
                            simpc_gatewayv6='::', simpc_mc_dstmac='00-00-00-00-00-00')
            for key in ('simpc_gateway', 'simpc_mc_dstip', 'simpc_dns1', 'simpc_dns2', 'simpc_group_ip_start', 'simpc_src_ip_start'):
                expected[key] = '0.0.0.0'
            for key, value in values:
                if key == 'simpc_mac':
                    continue
                if value != expected[key]:
                    raise ValueError(f'工程参数 {key} 超出已审查范围')
            settings = ' ' + '  '.join(f'-{k} {row["mac"] if k == "simpc_mac" else v}' for k, v in values) + ' '
        attrs.update(id=row['id'], name=name, model='S3700' if switch else 'PC', settings=settings,
                     system_mac=row['mac'], com_port=str(row['port']) if switch else '0', bootmode='0' if switch else '1')
        target = E.SubElement(out, 'dev', attrs)
        slot = E.SubElement(target, 'slot', number='slot17', isMainBoard='1')
        E.SubElement(slot, 'interface', sztype='Ethernet', interfacename='Ethernet' if switch else 'GE', count='22' if switch else '1')
        if switch:
            E.SubElement(slot, 'interface', sztype='Ethernet', interfacename='GE', count='2')
    lines = E.SubElement(topo, 'lines')
    actual = set()
    for line in source.findall('./lines/line'):
        a, b = [name_by_id[line.get(k)] for k in ('srcDeviceID', 'destDeviceID')]
        pair = line.find('interfacePair')
        ap, bp = int(pair.get('srcIndex')) + 1, int(pair.get('tarIndex')) + 1
        actual.add((a, ap, b, bp))
        ids = {**public['switches'], **public['pcs']}
        target = E.SubElement(lines, 'line', srcDeviceID=ids[a]['id'], destDeviceID=ids[b]['id'])
        E.SubElement(target, 'interfacePair', lineName='Copper', srcIndex=str(ap-1), tarIndex=str(bp-1))
    if actual != set(LINKS) or len(devices) != 8:
        raise ValueError('工程设备或连线与本题不符')
    E.SubElement(topo, 'shapes')
    E.SubElement(topo, 'txttips')
    E.indent(topo, space='    ')
    return topo


def export(source, destination, include_stp=False):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError('导出目录须独立于原始目录')
    original = json.loads((source.parent.parent / 'manifest.json').read_text('utf-8'))
    public = manifest_for(original)
    results = json.loads((source / 'results/核对结果.json').read_text('utf-8'))
    if not results['passed'] or results['issues'] or len(results['steps']) != 6:
        raise ValueError('输入轮次须有完整的六步记录及核对结果')
    inputs = {}
    payloads = {}
    def read(path):
        inputs[path.relative_to(source.parent.parent).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return path
    public_rows, frame_rows = [], []
    for step in range(6):
        for name in ('SW1', 'SW2', 'SW3'):
            path = read(source / f'step-{step}/{name}.txt')
            text = scrub_console(path.read_text('utf-8'), original)
            payloads[f'console/step-{step}/{name}.txt'] = text.encode('utf-8')
    captures, selected = [], []
    for a, _, b, _ in LINKS:
        link = a + '-' + b
        path = read(source / f'captures/{link}.pcap')
        kept, udp_steps = [], []
        for number, stamp, packet, wire in read_pcap(path):
            found = udp_packet(packet, original)
            if found:
                step, rewritten = found
                udp_steps.append(step)
                if wire != len(packet):
                    raise ValueError('不发布截断帧')
                kept.append((number, stamp, step, rewritten, wire))
            elif include_stp:
                if wire != len(packet):
                    raise ValueError('不发布截断帧')
                kept.append((number, stamp, 0, stp_packet(packet, original), wire))
        wanted = [1, 2, 3] + ([4] if link in {'Client4-SW3', 'SW2-SW3', 'Client3-SW2'} else []) + ([5] if link in {'Client5-SW3', 'Client4-SW3'} else [])
        if udp_steps != wanted:
            raise ValueError(f'{link} 的目标帧数量或顺序与实测核对结果不符')
        captures.append((link, kept))
        selected += kept
    origin = min(row[1] for row in selected)
    for link, kept in captures:
        data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (old_number, stamp, step, packet, wire) in enumerate(kept, 1):
            offset_us = (stamp - origin) // 1000
            sec, micro = divmod(offset_us, 1_000_000)
            data += struct.pack('<IIII', sec, micro, len(packet), wire) + packet
            frame_rows.append([link, i, old_number, 'UDP' if step else 'MSTP', f'{sec}.{micro:06d}',
                               packet[6:12].hex(':'), packet[:6].hex(':'), wire])
            if not step:
                continue
            src, dst = SEQUENCE[step-1]
            public_rows.append([link, i, old_number, step, f'{sec}.{micro:06d}',
                                public_mac(f'Client{src}').hex(':'), public_mac(f'Client{dst}').hex(':'),
                                f'192.0.2.{src}', f'192.0.2.{dst}', 29, 1, 1, 9, f'{step:02x}', wire])
        payloads[f'pcap/{link}.pcap'] = bytes(data)
    # 全部校验完成后才创建新目录；任何既有输出均保留。
    destination.mkdir(parents=True, exist_ok=False)
    for name, value in payloads.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    with (destination / 'udp-fields.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(['link', 'public_frame', 'source_frame', 'step', 'relative_seconds', 'eth.src', 'eth.dst',
                         'ip.src', 'ip.dst', 'ip.length', 'udp.srcport', 'udp.dstport', 'udp.length', 'data', 'wire_length'])
        writer.writerows(public_rows)
    with (destination / 'frames.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(['link', 'public_frame', 'source_frame', 'protocol', 'relative_seconds', 'eth.src', 'eth.dst', 'wire_length'])
        writer.writerows(frame_rows)
    write_text(destination / 'manifest.json', json.dumps(public, ensure_ascii=False, indent=2) + '\n')
    write_text(destination / 'tables.json', json.dumps({'kind': '仿真实测的脱敏副本', 'steps': results['steps']}, ensure_ascii=False, indent=2) + '\n')
    summary = scrub_console((source / 'results/实测结果.md').read_text('utf-8'), original)
    write_text(destination / '实测结果.md', summary.replace('# 交换机自学习实测结果', '# 交换机自学习实测结果（脱敏副本）', 1))
    with (destination / 'mac-tables.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(['数据性质', '步骤', '交换机', 'PC', 'MAC', '接口'])
        for row in results['steps']:
            for switch, table in row['tables'].items():
                for client, port in table.items():
                    writer.writerow(['仿真实测（MAC已替换）', row['step'], switch, f'Client{client}', public['pcs'][f'Client{client}']['mac'], f'E0/0/{port}'])
    inventory = {'data_kind': '仿真实测的脱敏副本', 'console_files': 18, 'links': 7, 'udp_frames': len(public_rows),
                 'stp_frames': len(frame_rows)-len(public_rows), 'total_frames': len(frame_rows),
                 'changes': ['PC 与交换机 MAC 一致替换为本地管理地址',
                             '保留五次目标 UDP 与全部 MSTP 帧；MST 配置名中的 MAC 一并替换' if include_stp else '仅保留五次目标 UDP 帧',
                             '所有链路时间共同平移，首帧为 0 秒，保留相对间隔', '设备 ID 重建；省略本机路径和运行环境信息',
                             '文本使用 UTF-8/LF；清理 Console 行尾空白和终端控制字符'],
                 'sha256': {p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(destination.rglob('*')) if p.is_file()}}
    write_text(destination / 'inventory.json', json.dumps(inventory, ensure_ascii=False, indent=2) + '\n')
    return public, inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path, help='含 step-0～5、captures、results 的原始轮次目录')
    parser.add_argument('--output', type=Path, required=True, help='尚不存在的独立输出目录')
    parser.add_argument('--include-stp', action='store_true', help='额外保留已校验并脱敏的本轮 MSTP 背景帧')
    args = parser.parse_args()
    export(args.run, args.output, include_stp=args.include_stp)
    print('已导出 18 份脱敏日志、7 份抓包及对应字段和表项。请逐项复核后再提交。')


if __name__ == '__main__':
    main()
