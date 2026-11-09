"""按课件拓扑推演五次单向以太网发包，输出符号表与模型示例 PCAP。"""
from __future__ import annotations

import argparse
import csv
import json
import socket
import struct
from collections import deque
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINKS = [
    ('Client1', 1, 'SW1', 1), ('Client2', 1, 'SW1', 3),
    ('SW1', 2, 'SW2', 1), ('Client3', 1, 'SW2', 3),
    ('SW2', 2, 'SW3', 1), ('Client4', 1, 'SW3', 3),
    ('Client5', 1, 'SW3', 2),
]
SEQUENCE = [(1, 5), (2, 4), (3, 5), (4, 3), (5, 4)]


@dataclass
class Entry:
    port: int
    seen: float


class Switch:
    def __init__(self, ports=(1, 2, 3), aging=0):
        self.ports = tuple(ports)
        self.aging = aging
        self.table: dict[tuple[int, str], Entry] = {}

    def expire(self, now):
        if self.aging:
            self.table = {k: v for k, v in self.table.items()
                          if now - v.seen < self.aging}

    def receive(self, src, dst, ingress, now, vlan=1):
        self.expire(now)
        if ingress not in self.ports:
            raise ValueError('入端口不在转发端口集合中')
        prior = self.table.get((vlan, src))
        learn = ('新增' if prior is None else
                 '迁移' if prior.port != ingress else '刷新')
        self.table[vlan, src] = Entry(ingress, now)
        target = self.table.get((vlan, dst))
        if target is None:
            return learn, '泛洪', [p for p in self.ports if p != ingress]
        if target.port == ingress:
            return learn, '过滤', []
        return learn, '单播', [target.port]

    def snapshot(self):
        return {mac: entry.port for (vlan, mac), entry in sorted(self.table.items())
                if vlan == 1}


def run():
    peers, edge_names = {}, {}
    for a, ap, b, bp in LINKS:
        peers[a, ap] = (b, bp)
        peers[b, bp] = (a, ap)
        edge_names[frozenset((a, b))] = f'{a}-{b}'
    switches = {n: Switch() for n in ('SW1', 'SW2', 'SW3')}
    steps, transmissions = [], []
    for step, (src, dst) in enumerate(SEQUENCE, 1):
        first, ingress = peers[f'Client{src}', 1]
        queue = deque([(first, ingress)])
        events, seen = [], set()
        transmissions.append((step, src, dst, edge_names[frozenset((f'Client{src}', first))]))
        while queue:
            name, ingress = queue.popleft()
            if name in seen:
                raise ValueError('拓扑出现重复到达，检查二层环路')
            seen.add(name)
            learn, action, outputs = switches[name].receive(f'C{src}', f'C{dst}', ingress, step)
            events.append(dict(switch=name, ingress=ingress, learn=learn,
                               source=f'C{src}', action=action, egress=outputs))
            for port in outputs:
                peer, peer_port = peers[name, port]
                transmissions.append((step, src, dst, edge_names[frozenset((name, peer))]))
                if peer in switches:
                    queue.append((peer, peer_port))
        steps.append(dict(step=step, source=src, destination=dst, events=events,
                          tables={n: s.snapshot() for n, s in switches.items()}))
    return dict(kind='理论模型', assumptions=['初始动态表为空', '同属VLAN 1',
                '关闭老化', '每步只发送指定单向帧', '全程保留已学习表项'],
                steps=steps), transmissions


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data)//2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def model_frame(src, dst, step):
    # 本地管理单播 MAC、文档用 IPv4 地址和显式 MODEL 负载。
    payload = f'MODEL CNEXP2 STEP{step}'.encode('ascii')
    udp = struct.pack('!HHHH', 50000 + step, 50000 + step, 8 + len(payload), 0) + payload
    fields = (0x45, 0, 20 + len(udp), step, 0, 64, 17, 0,
              socket.inet_aton(f'192.0.2.{src}'), socket.inet_aton(f'192.0.2.{dst}'))
    ip = struct.pack('!BBHHHBBH4s4s', *fields)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src, 8, 0])
    return (eth + ip + udp).ljust(60, b'\0')


def write_outputs(output):
    output.mkdir(parents=True, exist_ok=True)
    data, transmissions = run()
    (output/'推导结果.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf8')
    with (output/'逐步转发表.csv').open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['数据性质', '步骤', '发送', '交换机', '源MAC代号', '端口'])
        for s in data['steps']:
            for sw, table in s['tables'].items():
                for mac, port in table.items():
                    w.writerow(['理论推导', s['step'], f"{s['source']}→{s['destination']}", sw, mac, f'E0/0/{port}'])
    captures = output/'模型抓包'
    captures.mkdir(exist_ok=True)
    groups = {'all-links': []}
    for i, (step, src, dst, link) in enumerate(transmissions):
        packet = model_frame(src, dst, step)
        record = struct.pack('<IIII', 1700000000 + step, i * 1000, len(packet), len(packet)) + packet
        groups.setdefault(link, []).append(record)
        groups['all-links'].append(record)
    for link, records in groups.items():
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        (captures/f'model-{link}.pcap').write_bytes(header + b''.join(records))
    (captures/'说明.txt').write_text('这些 PCAP 由理论模型生成，使用示例地址、固定示例时间和 MODEL 负载。\n'
        '每个文件对应一条链路，all-links 合并各链路观察记录。\n', encoding='utf8')
    return data, transmissions


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'local'/'model')
    args = parser.parse_args()
    data, frames = write_outputs(args.output)
    print(f'完成理论推导：{len(data["steps"])} 步，{len(frames)} 条链路帧记录。')
