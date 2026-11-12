"""按课件顺序自动运行实验3的一个工程；用户预先打开设备、PC页与抓包。"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import socket
import sys
import time
import traceback

import collect_switches as collector
from lab_spec import EXPERIMENTS, TOPOLOGY_FILES
from prepare_topology import read_topology, validate_topology

ROOT = Path(__file__).resolve().parents[1]
STATUS_LABELS = {'completed': '实测和证据采集完成', 'evidence_pending': '实测已记录，仍有待补证据',
                 'needs_attention': '已停止，需按提示处理', 'ready_check_only': '准备条件核对通过',
                 'preparing': '准备中', 'running': '运行中', 'interrupted': '已中断'}


def now():
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='microseconds')


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def load_project(part, bundle=None):
    if part not in EXPERIMENTS:
        raise ValueError('请选择实验3的 part1 或 part2')
    folder = Path(bundle).resolve() if bundle else collector.latest_bundle()
    if not folder.is_relative_to((ROOT/'local').resolve()):
        raise ValueError('工程必须位于 exp3/local')
    manifest = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    path = folder/TOPOLOGY_FILES[part]
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest.get('files_sha256', {}).get(path.name):
        raise ValueError('准备工程的哈希与批次清单不同，请先核对打开的工程')
    topo = read_topology(path)
    validate_topology(topo, part, manifest)
    hosts, devices = {}, {d.get('name'): d for d in topo.findall('./devices/dev')}
    for name, host in EXPERIMENTS[part]['hosts'].items():
        settings = dict(re.findall(r'-(simpc_\w+)\s+(\S+)', devices[name].get('settings', '')))
        hosts[name] = {**host, 'mac': settings['simpc_mac'], 'device_id': devices[name].get('id')}
    metadata = {}
    for a, ap, b, bp in EXPERIMENTS[part]['links']:
        metadata[f'{a}-{b}'] = {'endpoints': [
            {'device_id': devices[name].get('id'), 'port_index': port-1, 'port': port,
             'interface_name': f'Ethernet0/0/{port}'} for name, port in ((a, ap), (b, bp))]}
    return folder, hosts, metadata


def plan(part):
    if part == 'part1':
        return [('part1-default', [('PC1', 'PC2', True), ('PC1', 'PC3', True), ('PC1', 'PC4', True)]),
                ('part1-vlan2', [('PC1', 'PC2', True), ('PC1', 'PC3', False), ('PC1', 'PC4', False)])]
    if part == 'part2':
        return [('part2-access', [('PC1', 'PC2', False)]),
                ('part2-routing', [('PC1', 'PC3', True), ('PC3', 'PC1', True),
                                   ('PC1', 'PC2', True), ('PC2', 'PC1', True), ('PC1', 'PC4', True)])]
    raise ValueError('未知工程')


def required_sources(part):
    return sorted({source for _, tests in plan(part) for source, _, _ in tests})


def capture_items(exported):
    evidence = exported.get('capture_evidence', {})
    return list(evidence.values()) if isinstance(evidence, dict) else evidence


def forwarding_evidence(exported, source_ip, target_ip, cross_vlan):
    """跨观察点匹配同一完整ICMP请求，保留原帧引用而不补造字段。"""
    groups = {}
    for item in capture_items(exported):
        for row in item.get('analysis', {}).get('frames', []):
            if (row.get('source_ip'), row.get('destination_ip'), row.get('icmp_type')) != (source_ip, target_ip, 8):
                continue
            if not row.get('icmp_complete'):
                continue
            key = (row.get('icmp_id'), row.get('icmp_seq'), row.get('icmp_payload_hex'))
            groups.setdefault(key, []).append({'link': item.get('link'), 'source_frame': row.get('source_frame'),
                'ttl': row.get('ip_ttl'), 'source_mac': row.get('source_mac'), 'destination_mac': row.get('destination_mac'),
                'vlans': [tag['vlan'] for tag in row.get('vlan_tags', [])]})
    result = []
    for (ident, seq, _), copies in groups.items():
        good = False
        if cross_vlan:
            for before in copies:
                for after in copies:
                    if (before['vlans'] and after['vlans'] and before['vlans'] != after['vlans'] and
                        isinstance(before['ttl'], int) and isinstance(after['ttl'], int) and
                        before['ttl'] == after['ttl']+1 and
                        (before['source_mac'], before['destination_mac']) != (after['source_mac'], after['destination_mac'])):
                        good = True
        else:
            good = (len({x['link'] for x in copies}) > 1 and len({x['ttl'] for x in copies}) == 1 and
                    None not in {x['ttl'] for x in copies} and
                    all(x['source_mac'] and x['destination_mac'] for x in copies) and
                    len({(x['source_mac'], x['destination_mac']) for x in copies}) == 1)
        result.append({'icmp_id': ident, 'icmp_seq': seq, 'copies': copies,
                       'cross_vlan': cross_vlan, 'forwarding_observed': good})
    return result


def state_issues(part, name, responses, routed=False):
    """只检查真实回读；未识别的接口/STP状态保留为待就绪。"""
    ports = sorted({ap if a == name else bp for a, ap, b, bp in EXPERIMENTS[part]['links'] if name in (a, b)})
    physical = {}
    for line in responses['display interface brief'].splitlines():
        m = re.match(r'^\s*(?:Ethernet|Eth)0/0/(\d+)\s+(\S+)\s+(\S+)', line, re.I)
        if m:
            physical[int(m[1])] = (m[2].lower(), m[3].lower())
    issues = [f'{name} Ethernet0/0/{p} 尚未 up/up' for p in ports if physical.get(p) != ('up', 'up')]
    stp = responses['display stp brief']
    disabled = bool(re.search(r'(?:STP.*(?:disabled|not.*enabled)|not.*enabled.*STP)', stp, re.I))
    if not disabled:
        forwarding = {int(m[1]) for line in stp.splitlines()
                      if (m := re.search(r'(?:Ethernet|Eth)0/0/(\d+)\b.*\bFORWARDING\b', line, re.I))}
        issues += [f'{name} Ethernet0/0/{p} STP 转发状态待就绪' for p in ports if p not in forwarding]
    if routed and name == 'S1':
        brief = responses['display ip interface brief']
        for vlan in (100, 200):
            row = next((line for line in brief.splitlines() if re.match(fr'^\s*Vlanif\s*{vlan}\s', line, re.I)), '')
            if len(re.findall(r'\bup\b', row, re.I)) < 2:
                issues.append(f'S1 Vlanif{vlan} 尚未 up/up')
    return issues


def query_console(port, commands, output):
    """只有 runner 固定查询和 ARP 清表命令可进入这里；目标始终为本机工程端口。"""
    transcript, responses = [], {}
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
            sock.settimeout(0.3)
            sock.sendall(b'\r\n')
            banner = collector.read_prompt(sock)
            transcript.append(banner)
            if banner.rstrip().endswith(']'):
                sock.sendall(b'return\r\n')
                transcript.append(collector.read_prompt(sock))
            for command in commands:
                transcript.append('COMMAND: '+command+'\n')
                sock.sendall(command.encode('ascii')+b'\r\n')
                try:
                    answer = collector.read_prompt(sock)
                except collector.ConsoleError as exc:
                    transcript.append(exc.partial)
                    raise
                transcript.append(answer)
                responses[command] = answer
                if collector.ERROR.search(answer):
                    raise RuntimeError('设备命令失败：'+command)
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('\n\n'.join(transcript), encoding='utf-8')
    return responses


def validate_protocol_evidence(summaries):
    """第二部分要求的协议类别按帧内容核对，配置推导不参与替代。"""
    echo = [g for s in summaries for g in s.get('icmp_echo_groups', []) if g.get('matched_pairs', 0)]
    arp = [g for s in summaries for g in s.get('arp_groups', []) if g.get('matched_pairs', 0)]
    missing = []
    for relation, label in [('same_vlan', '同VLAN ICMP请求/应答'), ('cross_vlan', '跨VLAN ICMP请求/应答')]:
        if not any(g.get('vlan_relation') == relation for g in echo):
            missing.append(label)
    for source, target, label in [
        ('192.168.100.1', '192.168.100.3', '同网段PC1查询PC3的ARP请求/应答'),
        ('192.168.100.1', '192.168.100.254', '跨网段PC1查询网关的ARP请求/应答'),
        ('192.168.200.254', '192.168.200.2', '跨网段S1查询PC2的ARP请求/应答')]:
        if not any(g.get('requester_ip') == source and g.get('target_ip') == target for g in arp):
            missing.append(label)
    return missing


class ProjectRunner:
    def __init__(self, part, bundle=None, *, mapping=None, pc_factory=None, capture_factory=None,
                 collect_fn=None, guard_fn=None, query_fn=None, analyze_fn=None, progress=print,
                 sleep=time.sleep, kind='eNSP实测', interactive=False):
        self.part = part
        self.bundle, self.hosts, self.link_metadata = load_project(part, bundle)
        self.ports = list(EXPERIMENTS[part]['switches'].values())
        cached_mapping = ROOT/'local'/'state'/f'{part}-capture-map.json'
        self.mapping = (json.loads(cached_mapping.read_text(encoding='utf-8'))
                        if mapping is None and cached_mapping.exists() else mapping)
        self.pc_factory, self.capture_factory = pc_factory, capture_factory
        self.collect_fn = collect_fn or collector.collect
        self.guard_fn = guard_fn or collector.runtime_guard
        self.query_fn = query_fn or query_console
        self.analyze_fn = analyze_fn
        self.progress, self.sleep = progress, sleep
        self.interactive = interactive
        self.prepare_attempt = 0
        self.folder = ROOT/'local'/'runs'/(datetime.now(timezone(timedelta(hours=8))).strftime('%Y%m%dT%H%M%S.%f%z')+'-'+part)
        self.folder.mkdir(parents=True, exist_ok=False)
        self.record = {'kind': kind, 'part': part, 'bundle': str(self.bundle), 'started_at': now(),
                       'status': 'preparing', 'pings': [], 'stages': [], 'events': [], 'missing': [],
                       'manual_actions': [], 'observations': [],
                       'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        self.pc, self.captures = None, None
        self.flush()

    def event(self, detail):
        self.progress(detail)
        self.record['events'].append({'at': now(), 'detail': detail})
        self.flush()

    def flush(self):
        save_json(self.folder/'run.json', self.record)
        self.write_notes()

    def write_notes(self):
        lines = ['# 实验3本轮记录', '', '数据类别：'+self.record['kind'],
                 '工程：'+self.part+'；状态：'+STATUS_LABELS.get(self.record['status'], self.record['status']), '',
                 '| 阶段 | 源PC | 目标PC | 理论预期 | 实测发送/接收 | 核对结果 |',
                 '| --- | --- | --- | --- | --- | --- |']
        for row in self.record['pings']:
            actual = row['actual']
            lines.append(f'| {row["stage"]} | {row["source"]} | {row["target"]} | '
                         f'{"通" if row["expected"] else "不通"} | {actual.get("sent", "待核")}/{actual.get("received", "待核")} | '
                         f'{"符合预期" if row["matches_expected"] else "待排查"} |')
        lines += ['', '## PC参数实际回读', '', '| PC | IPv4 | 掩码 | 网关 | MAC |', '| --- | --- | --- | --- | --- |']
        for source, identity in self.record.get('pc_probe', {}).get('hosts', {}).items():
            lines.append('| '+' | '.join(str(v or '待回读') for v in [source, identity.get('observed_ip'),
                         identity.get('observed_mask'), identity.get('observed_gateway'), identity.get('observed_mac')])+' |')
        lines += ['', '## 交换机配置与发包后表项', '']
        for stage in self.record['stages']:
            lines.append('- '+stage['stage']+'：配置回读 '+stage['configuration']+'；发包后回读 '+stage.get('after_ping', '待采集'))
            if stage.get('after_ping'):
                for device in EXPERIMENTS[self.part]['switches']:
                    path = Path(stage['after_ping'])/(device+'.txt')
                    if not path.exists():
                        continue
                    original = path.read_text(encoding='utf-8')
                    for command in ('display mac-address', 'display arp', 'display ip routing-table'):
                        match = re.search(r'(?ms)^COMMAND: '+re.escape(command)+r'\n(.*?)(?=^COMMAND: |\Z)', original)
                        if match:
                            lines += ['', f'### {stage["stage"]} / {device} / {command}（实测原文）',
                                      '', '```text', match[1].strip(), '```', '']
        lines += ['', '## 抓包分析实际统计', '',
                  '| 阶段/链路 | 帧数 | VLAN标签 | Echo请求/应答 | ARP请求/应答 |',
                  '| --- | --- | --- | --- | --- |']
        for stage in self.record['stages']:
            for item in stage.get('analysis', []):
                summary = item['summary']
                counts = summary.get('protocol_counts', {})
                lines.append(f'| {stage["stage"]}/{item.get("link")} | {summary.get("total_frames", "待核")} | '
                             f'{",".join(summary.get("observed_vlan_ids", {})) or "无标签"} | '
                             f'{counts.get("icmp_echo_requests", 0)}/{counts.get("icmp_echo_replies", 0)} | '
                             f'{counts.get("arp_requests", 0)}/{counts.get("arp_replies", 0)} |')
        lines += ['', '## 三层转发与二层转发的逐帧对照', '']
        for row in self.record['pings']:
            observed = next((x for x in row.get('forwarding_evidence', []) if x.get('forwarding_observed')), None)
            if not observed:
                continue
            lines += [f'### {row["source"]}到{row["target"]}，ICMP标识符{observed["icmp_id"]}、序号{observed["icmp_seq"]}', '',
                      '| 观察链路 | 原帧号 | VLAN标签 | TTL | 源MAC | 目的MAC |', '| --- | --- | --- | --- | --- | --- |']
            for copy in observed['copies']:
                lines.append('| '+' | '.join(str(v) for v in [copy['link'], copy['source_frame'],
                             ','.join(map(str, copy['vlans'])) or '无标签', copy['ttl'],
                             copy['source_mac'], copy['destination_mac']])+' |')
            lines += ['']
        lines += ['', '原始命令输出、清表记录、设备回读、截图与抓包路径详见 run.json。', '', '## 待补证据或人工操作', '']
        items = self.record['missing']+self.record['manual_actions']
        lines += ['- '+str(item) for item in items] or ['当前没有列出的缺项；最终状态见上方。']
        lines += ['', '## 实际观察', ''] + ['- '+str(x) for x in self.record['observations']]
        (self.folder/'实测记录.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')

    def prepare(self):
        self.prepare_attempt += 1
        stage = plan(self.part)[0][0]
        self.event('正在核对工程和 Console 归属')
        guard = self.guard_fn(stage, self.ports, self.bundle)
        self.record['runtime_guard'] = guard
        owner = guard.get('console_owners', [{}])[0].get('PID')
        if not owner:
            raise RuntimeError('未核对到 eNSP Console 所属进程')
        if self.pc_factory is None:
            from pc_console import PCConsole
            self.pc_factory = PCConsole
        self.pc = self.pc_factory(owner, self.hosts)
        self.event('正在回读PC身份和参数：'+', '.join(required_sources(self.part)))
        probe = self.pc.probe(required_sources(self.part), output_dir=self.folder/'pc-identity'/f'attempt-{self.prepare_attempt}')
        self.record['pc_probe'] = probe
        if probe.get('status') != 'ready':
            raise RuntimeError('请打开必要PC的“命令行”页并保持打开：'+', '.join(required_sources(self.part)))
        if self.capture_factory is None:
            from capture_workflow import CaptureSession
            self.capture_factory = CaptureSession
        self.captures = self.capture_factory(list(self.link_metadata), self.hosts, self.folder/'captures',
                                             mapping=self.mapping, link_metadata=self.link_metadata,
                                             require_active=True,
                                             kind='测试夹具' if self.record['kind'] == '测试夹具' else '实测抓包')
        discovery = self.captures.discover()
        if discovery.get('needs_input') and self.interactive:
            self.event('将按链路逐条提示开始抓包；每条只需手动开启一次，保持窗口运行')
            discovery = self.captures.enroll_missing(progress=self.event)
        self.record['capture_discovery'] = discovery
        if discovery.get('captures'):
            self.mapping = {item['link']: item for item in discovery['captures']}
            save_json(self.folder/'capture-map.json', self.mapping)
            save_json(ROOT/'local'/'state'/f'{self.part}-capture-map.json', self.mapping)
        if discovery.get('status') != 'ready':
            save_json(self.folder/'capture-mapping-needed.json', discovery)
            raise RuntimeError('抓包尚未按链路就绪；请手动开始各链路抓包，映射提示见 capture-mapping-needed.json')
        self.event('PC与抓包预检完成，开始按课件顺序运行')

    def checkpoint(self, label):
        result = self.captures.checkpoint(label)
        if result.get('status') != 'ready' or not result.get('token'):
            self.record['missing'] += [str(x) for x in result.get('missing', [])]
            raise RuntimeError('抓包检查点未就绪，尚未执行对应ping：'+label)
        return result

    def export(self, label, checkpoint, expectations=None):
        result = self.captures.export_phase(label, checkpoint=checkpoint, expectations=expectations)
        self.record['missing'] += [str(x) for x in result.get('missing', [])]
        if (result.get('status') != 'complete' or result.get('missing') or
                {item.get('link') for item in capture_items(result)} != set(self.link_metadata)):
            save_json(self.folder/'capture-export-failure.json', result)
            raise RuntimeError('抓包窗口或链路证据不完整；已停止，保留本轮数据及 capture-export-failure.json')
        return result

    def wait_ready(self, stage, timeout=50):
        deadline = time.monotonic()+timeout
        attempt = 0
        while True:
            attempt += 1
            issues = []
            for name, port in EXPERIMENTS[self.part]['switches'].items():
                commands = ['display interface brief', 'display stp brief', 'display ip interface brief']
                output = self.folder/'readiness'/stage/f'{attempt:02d}-{name}.txt'
                responses = self.query_fn(port, commands, output)
                issues += state_issues(self.part, name, responses, stage == 'part2-routing')
            if not issues:
                self.event('接口与转发状态已就绪：'+stage)
                return
            self.event('等待链路收敛：'+'；'.join(issues))
            if time.monotonic() >= deadline:
                raise RuntimeError('链路或Vlanif状态未就绪；已保存每次回读，尚未发起本阶段ping')
            self.sleep(2)

    def clear_core_arp(self, label):
        self.guard_fn('part2-routing', self.ports, self.bundle)
        commands = ['reset arp dynamic', 'display arp']
        output = self.folder/'arp'/label/'S1.txt'
        response = self.query_fn(EXPERIMENTS[self.part]['switches']['S1'], commands, output)
        remaining = [h['ip'] for h in self.hosts.values() if re.search(r'(?<![\d.])'+re.escape(h['ip'])+r'(?![\d.])', response['display arp'])]
        if remaining:
            raise RuntimeError('S1动态ARP清理后仍有实验主机表项，已保留回读，请核查')

    def ping(self, stage, source, target, expected, index):
        label = f'{index:02d}-{source}-{target}'
        folder = self.folder/'pings'/stage/label
        self.event(f'{stage}：自动 {source} ping {self.hosts[target]["ip"]}，4次')
        clear = self.pc.clear_arp(source, output_dir=folder/'arp')
        if clear.get('status') != 'completed' or not clear.get('verified_clear'):
            raise RuntimeError(f'{source} ARP清理未核对成功；请查看原始命令输出')
        if stage == 'part2-routing' and self.hosts[source]['vlan'] != self.hosts[target]['vlan']:
            self.clear_core_arp(label)
        checkpoint = self.checkpoint(stage+'-'+label)
        actual = self.pc.ping(source, self.hosts[target]['ip'], count=4, output_dir=folder)
        known = actual.get('status') == 'completed' and actual.get('sent') == 4 and not actual.get('unknown')
        received = actual.get('received')
        matches = bool(known and isinstance(received, int) and ((received > 0) if expected else received == 0))
        self.record['pings'].append({'stage': stage, 'source': source, 'target': target,
                                    'expected': expected, 'actual': actual, 'matches_expected': matches})
        if actual.get('manual_stop_required'):
            self.record['manual_actions'].append(f'请在{source}命令行页按Ctrl+C，核对ping已停止；助手不会重发')
        if not actual.get('screenshot'):
            self.record['missing'].append(f'{stage} {source}→{target} 的现场截图（自动截图未取得）')
        self.flush()
        self.sleep(1)
        evidence = self.export(stage+'-'+label, checkpoint,
                               [{'source': source, 'target': target, 'reachable': expected,
                                 'allow_gateway_arp': stage == 'part2-access' and not expected}])
        self.record['pings'][-1]['capture'] = evidence
        if expected and isinstance(received, int) and 0 < received < 4:
            self.record['observations'].append(f'{stage} {source}→{target} 本次接收{received}/4，保留实际丢包统计')
        if stage == 'part2-routing' and matches:
            cross = self.hosts[source]['vlan'] != self.hosts[target]['vlan']
            compared = forwarding_evidence(evidence, self.hosts[source]['ip'], self.hosts[target]['ip'], cross)
            self.record['pings'][-1]['forwarding_evidence'] = compared
            if not any(x['forwarding_observed'] for x in compared):
                self.record['missing'].append(f'{source}→{target} 跨观察点的MAC/TTL'+('及VLAN切换' if cross else '保持')+'对照证据')
        self.record['missing'] += [str(x) for x in evidence.get('missing', [])]
        self.flush()
        if not matches:
            raise RuntimeError(f'{source}→{target} 的实际ping结果待核查，已停止后续配置并保留本轮数据')

    def analyze_phase(self, stage, exported):
        if self.analyze_fn is None:
            from analyze_capture import analyze
            self.analyze_fn = analyze
        summaries, results = [], []
        for capture in capture_items(exported):
            path = capture.get('window_path') or capture.get('file') or capture.get('path')
            if not path:
                self.record['missing'].append('阶段抓包没有可解析文件路径：'+stage)
                continue
            self.event('离线分析：'+str(capture.get('link', Path(path).name)))
            folder, summary = self.analyze_fn(path, scenario='port-vlan' if self.part == 'part1' else 'inter-vlan',
                                            kind='测试夹具' if self.record['kind'] == '测试夹具' else '实测抓包')
            results.append({'link': capture.get('link'), 'result_directory': str(folder), 'summary': summary})
            summaries.append(summary)
        if not results:
            self.record['missing'].append('阶段抓包分析：'+stage)
        if stage == 'part2-routing':
            self.record['missing'] += validate_protocol_evidence(summaries)
        return results

    def run(self, check_only=False, wait_seconds=0):
        self.record['operation'] = 'preflight_only' if check_only else 'project_run'
        try:
            deadline = time.monotonic()+max(0, wait_seconds)
            if check_only:
                self.interactive = False
            while True:
                try:
                    self.prepare()
                    break
                except Exception as exc:
                    if check_only or time.monotonic() >= deadline:
                        raise
                    self.event('等待准备条件：'+str(exc))
                    self.sleep(3)
            if check_only:
                self.record['status'] = 'ready_check_only'
                return self.folder
            self.record['status'] = 'running'
            self.flush()
            for stage, tests in plan(self.part):
                self.event('配置并回读：'+stage)
                initial = self.collect_fn(stage, self.ports, apply=True, output_root=self.folder/'console', bundle=self.bundle)
                self.wait_ready(stage)
                start = self.checkpoint(stage)
                stage_record = {'stage': stage, 'started_at': now(), 'configuration': str(initial)}
                self.record['stages'].append(stage_record)
                for index, (source, target, expected) in enumerate(tests, 1):
                    self.ping(stage, source, target, expected, index)
                final = self.collect_fn(stage, self.ports, output_root=self.folder/'console-after', bundle=self.bundle)
                stage_record['after_ping'] = str(final)
                captures = self.export(stage, start)
                stage_record['captures'] = captures
                self.record['missing'] += [str(x) for x in captures.get('missing', [])]
                stage_record['analysis'] = self.analyze_phase(stage, captures)
                stage_record['finished_at'] = now()
                self.flush()
            self.record['status'] = 'evidence_pending' if self.record['missing'] else 'completed'
            self.event('本轮自动操作结束，实际记录已填写；'+STATUS_LABELS[self.record['status']])
        except KeyboardInterrupt:
            self.record['status'] = 'interrupted'
            self.record['manual_actions'].append('请核对PC是否仍有ping在运行，必要时在PC页Ctrl+C停止')
            raise
        except Exception as exc:
            self.record.update(status='needs_attention', error=str(exc))
            (self.folder/'diagnostic.txt').write_text(traceback.format_exc(), encoding='utf-8')
            self.event('已在当前步骤停止：'+str(exc))
        finally:
            self.record['finished_at'] = now()
            self.flush()
        return self.folder


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('part', choices=EXPERIMENTS)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--capture-map', type=Path, help='本地JSON文件：链路名称到活动抓包文件的对应关系')
    parser.add_argument('--check', action='store_true', help='只核对运行条件，不配置、不ping')
    parser.add_argument('--plan', action='store_true', help='仅显示操作计划，不读取窗口或连接设备')
    parser.add_argument('--wait', type=float, default=90, help='等候设备/必要PC就绪的秒数，默认90')
    args = parser.parse_args(argv)
    if args.plan:
        print(json.dumps({'kind': '操作计划，非实测', 'part': args.part, 'required_pc_pages': required_sources(args.part),
                          'stages': plan(args.part)}, ensure_ascii=False, indent=2))
        return 0
    mapping = json.loads(args.capture_map.read_text(encoding='utf-8')) if args.capture_map else None
    runner = ProjectRunner(args.part, args.bundle, mapping=mapping, interactive=not args.check)
    print('请打开当前批次的工程并启动设备；若提示PC窗口未准备好，再打开相应PC命令行页：'+', '.join(required_sources(args.part)))
    print('助手会逐条提示需要开始抓包的链路；每条手动开启一次即可，其余发包、采集、保存和填写自动完成。')
    folder = runner.run(args.check, wait_seconds=0 if args.check else args.wait)
    print('本轮目录：'+str(folder))
    return 0 if runner.record['status'] in ('completed', 'ready_check_only') else 1


if __name__ == '__main__':
    sys.exit(main())
