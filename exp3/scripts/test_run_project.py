"""以临时工程和依赖注入检验阶段编排；不启动UI、不连接设备、不发真实ping。"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_project as r
from lab_spec import EXPERIMENTS
from prepare_topology import generate_bundle


def protocol_summary():
    """只供本文件使用的协议测试夹具，绝不标作eNSP实测。"""
    return {
        'data_kind': '测试夹具',
        'icmp_echo_groups': [
            {'vlan_relation': relation, 'matched_pairs': 4}
            for relation in ('same_vlan', 'cross_vlan')],
        'arp_groups': [
            {'requester_ip': a, 'target_ip': b, 'matched_pairs': 1}
            for a, b in (
                ('192.168.100.1', '192.168.100.3'),
                ('192.168.100.1', '192.168.100.254'),
                ('192.168.200.254', '192.168.200.2'))],
    }


def forwarding_frames(hosts):
    """构造两观察点ICMP请求；内容仅为编排验收的测试输入。"""
    result = {'S1-S2': [], 'S1-S3': []}
    for index, (a, b) in enumerate((('PC1', 'PC3'), ('PC3', 'PC1'),
                                   ('PC1', 'PC2'), ('PC2', 'PC1'), ('PC1', 'PC4')), 1):
        source, target = hosts[a], hosts[b]
        cross = source['vlan'] != target['vlan']
        for point, link in enumerate(result):
            result[link].append({
                'source_ip': source['ip'], 'destination_ip': target['ip'],
                'icmp_type': 8, 'icmp_complete': True, 'icmp_id': index,
                'icmp_seq': 1, 'icmp_payload_hex': '746573742066697874757265',
                'source_frame': index*10+point,
                'ip_ttl': 64-point if cross else 64,
                'source_mac': '02:00:00:00:00:01' if not point or not cross else '02:00:00:00:00:fe',
                'destination_mac': '02:00:00:00:00:fe' if not point or not cross else '02:00:00:00:00:02',
                'vlan_tags': [{'vlan': source['vlan'] if not point else target['vlan']}],
            })
    return result


class FakePC:
    def __init__(self, owner, hosts, harness):
        self.owner, self.hosts, self.h = owner, hosts, harness

    def probe(self, names, output_dir):
        self.h.events.append(('probe', tuple(names)))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return {'status': self.h.probe_status, 'kind': '测试夹具'}

    def clear_arp(self, source, output_dir):
        self.h.events.append(('clear_pc', self.h.stage, source))
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        (Path(output_dir)/'arp.txt').write_text('TEST FIXTURE arp -d *\narp -a\n', encoding='utf-8')
        return {'status': 'completed', 'verified_clear': self.h.arp_clear}

    def ping(self, source, ip, count, output_dir):
        target = next(n for n, host in self.hosts.items() if host['ip'] == ip)
        self.h.events.append(('ping', self.h.stage, source, target, count))
        folder = Path(output_dir)
        folder.mkdir(parents=True, exist_ok=True)
        (folder/'ping.txt').write_text('TEST FIXTURE: NOT A REAL PING\n', encoding='utf-8')
        expected = next(ok for stage, tests in r.plan(self.h.part) if stage == self.h.stage
                        for a, b, ok in tests if (a, b) == (source, target))
        actual = {'status': 'completed', 'sent': count, 'received': count if expected else 0,
                  'unknown': False, 'source': '测试夹具'}
        if self.h.screenshots:
            # 本文件只验证字段编排，不生成或冒充真实现场截图。
            actual['screenshot'] = str(folder/'test-fixture-screenshot.png')
        if self.h.ping_override is not None:
            actual.update(self.h.ping_override)
        return actual


class FakeCapture:
    def __init__(self, links, hosts, output, harness, **kwargs):
        self.links, self.hosts, self.output, self.h = links, hosts, Path(output), harness
        self.output.mkdir(parents=True, exist_ok=True)
        self.h.capture_kwargs = kwargs

    def discover(self):
        self.h.events.append(('discover',))
        return {'status': self.h.discovery_status, 'needs_input': self.h.discovery_status != 'ready',
                'captures': [{'link': link} for link in self.links]}

    def enroll_missing(self, progress):
        self.h.events.append(('enroll',))
        raise AssertionError('非交互或check模式不应请求抓包注册')

    def checkpoint(self, label):
        self.h.events.append(('checkpoint', label))
        if self.h.fail_checkpoint and (self.h.fail_checkpoint == '*' or self.h.fail_checkpoint in label):
            return {'status': 'needs_attention', 'missing': ['TEST FIXTURE capture checkpoint missing']}
        return {'status': 'ready', 'token': 'test-token-'+label}

    def export_phase(self, label, checkpoint, expectations=None):
        self.h.events.append(('export', label))
        self.h.export_expectations.append((label, expectations))
        if self.h.export_error:
            raise RuntimeError('TEST FIXTURE capture rotation failure')
        frames = forwarding_frames(self.hosts) if self.h.part == 'part2' else {}
        items = {}
        for link in self.links:
            window = self.output/(label+'-'+link+'.pcap')
            window.write_bytes(b'TEST FIXTURE: NOT A REAL CAPTURE')
            items[link] = {'link': link, 'window_path': str(window),
                           'analysis': {'frames': frames.get(link, [])}}
        return {'status': self.h.export_status, 'capture_evidence': items,
                'missing': list(self.h.capture_missing)}


class Harness:
    def __init__(self, root, bundle, part):
        self.root, self.bundle, self.part = root, bundle, part
        self.events, self.stage = [], None
        self.probe_status = self.discovery_status = 'ready'
        self.export_status = 'complete'
        self.arp_clear = self.screenshots = True
        self.fail_checkpoint = self.ping_override = self.analyzer_summary = None
        self.export_error = self.guard_error = self.query_down = False
        self.capture_missing, self.capture_kwargs, self.export_expectations = [], {}, []

    def guard(self, stage, ports, bundle):
        self.events.append(('guard', stage))
        if self.guard_error:
            raise RuntimeError('TEST FIXTURE wrong project')
        return {'console_owners': [{'PID': 123}], 'kind': '测试夹具'}

    def collect(self, stage, ports, apply=False, output_root=None, bundle=None):
        self.events.append(('collect', stage, apply))
        if apply:
            self.stage = stage
        path = Path(output_root)/stage
        path.mkdir(parents=True, exist_ok=True)
        (path/'manifest.json').write_text(json.dumps({'kind': '测试夹具'}), encoding='utf-8')
        return path

    def query(self, port, commands, output):
        self.events.append(('query', port, tuple(commands)))
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        physical = '\n'.join(f'Ethernet0/0/{p} up up 0% 0% 0 0' for p in range(1, 23))
        stp = '\n'.join(f'0 Ethernet0/0/{p} DESI FORWARDING NONE' for p in range(1, 23))
        brief = 'Vlanif100 192.168.100.254/24 up up\nVlanif200 192.168.200.254/24 up up'
        if self.query_down:
            physical = physical.replace('up up', 'down down')
            stp = stp.replace('FORWARDING', 'DISCARDING')
            brief = brief.replace('up up', 'down down')
        answers = {'display interface brief': physical, 'display stp brief': stp,
                   'display ip interface brief': brief,
                   'reset arp dynamic': '<S1>', 'display arp': 'IP ADDRESS MAC ADDRESS EXPIRE(M) TYPE INTERFACE VPN-INSTANCE\nTotal:0'}
        responses = {command: answers[command] for command in commands}
        path.write_text('TEST FIXTURE\n'+json.dumps(responses), encoding='utf-8')
        return responses

    def analyze(self, path, **kwargs):
        self.events.append(('analyze', str(path), kwargs['scenario'], kwargs['kind']))
        return Path(path).parent/'test-fixture-analysis', (self.analyzer_summary if self.analyzer_summary is not None else protocol_summary())

    def runner(self, **kwargs):
        return r.ProjectRunner(self.part, self.bundle,
            pc_factory=lambda owner, hosts: FakePC(owner, hosts, self),
            capture_factory=lambda links, hosts, output, **kw: FakeCapture(links, hosts, output, self, **kw),
            collect_fn=self.collect, guard_fn=self.guard, query_fn=self.query,
            analyze_fn=self.analyze, progress=lambda value: None, sleep=lambda seconds: None,
            kind='测试夹具', interactive=False, **kwargs)

    def pings(self):
        return [event for event in self.events if event[0] == 'ping']

    def applied(self):
        return [event[1] for event in self.events if event[0] == 'collect' and event[2]]


class RunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        decision = self.root/'local'/'state'/'decisions.json'
        decision.parent.mkdir(parents=True)
        decision.write_text(json.dumps({'port_range': {'status': 'confirmed', 'interface': 'Ethernet',
            'source': 'user', 'note': '用户已确认；此文件为测试夹具'}}), encoding='utf-8')
        self.bundle, _ = generate_bundle(self.root/'local'/'topology', run_id='runner-test-fixture', decisions_path=decision)
        patcher = patch.object(r, 'ROOT', self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def harness(self, part='part1'):
        return Harness(self.root, self.bundle, part)

    def test_part1_completes_six_pings_in_ppt_order_and_preserves_isolation(self):
        h = self.harness()
        runner = h.runner()
        folder = runner.run()
        record = json.loads((folder/'run.json').read_text(encoding='utf-8'))
        self.assertEqual(record['kind'], '测试夹具')
        self.assertEqual(record['status'], 'completed')
        self.assertEqual(h.applied(), ['part1-default', 'part1-vlan2'])
        self.assertEqual([(x[1], x[3], x[4]) for x in h.pings()],
                         [(stage, target, 4) for stage in ('part1-default', 'part1-vlan2')
                          for target in ('PC2', 'PC3', 'PC4')])
        self.assertEqual([x['actual']['received'] for x in record['pings']], [4, 4, 4, 4, 0, 0])
        self.assertTrue(all(x['matches_expected'] for x in record['pings']))
        self.assertTrue(all('after_ping' in x and 'analysis' in x for x in record['stages']))
        self.assertEqual([x[1] for x in h.events if x[0] == 'probe'], [('PC1',)])
        self.assertFalse(any(x[0] == 'enroll' for x in h.events))
        self.assertTrue((folder/'实测记录.md').is_file())

    def test_part2_completes_six_pings_and_three_switch_after_records(self):
        h = self.harness('part2')
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'completed', runner.record['missing'])
        self.assertEqual(h.applied(), ['part2-access', 'part2-routing'])
        self.assertEqual([(x[1], x[2], x[3]) for x in h.pings()],
            [('part2-access', 'PC1', 'PC2'), ('part2-routing', 'PC1', 'PC3'),
             ('part2-routing', 'PC3', 'PC1'), ('part2-routing', 'PC1', 'PC2'),
             ('part2-routing', 'PC2', 'PC1'), ('part2-routing', 'PC1', 'PC4')])
        self.assertEqual(runner.record['pings'][0]['actual']['received'], 0)
        self.assertTrue(all(row['matches_expected'] for row in runner.record['pings']))
        self.assertEqual([x[1] for x in h.events if x[0] == 'probe'], [('PC1', 'PC2', 'PC3')])
        for row in runner.record['pings'][1:]:
            self.assertTrue(any(item['forwarding_observed'] for item in row['forwarding_evidence']))
        self.assertTrue(any(x == ('collect', 'part2-routing', False) for x in h.events))
        self.assertEqual(h.capture_kwargs['kind'], '测试夹具')
        self.assertTrue(all(x[3] == '测试夹具' for x in h.events if x[0] == 'analyze'))

    def test_every_ping_has_arp_clear_and_ready_capture_before_send(self):
        h = self.harness('part2')
        runner = h.runner()
        runner.run()
        previous_ping = -1
        for index, event in enumerate(h.events):
            if event[0] != 'ping':
                continue
            preceding = h.events[previous_ping+1:index]
            self.assertIn(('clear_pc', event[1], event[2]), preceding)
            self.assertEqual(preceding[-1][0], 'checkpoint')
            if event[1] == 'part2-routing' and EXPERIMENTS['part2']['hosts'][event[2]]['vlan'] != EXPERIMENTS['part2']['hosts'][event[3]]['vlan']:
                self.assertTrue(any(x[0] == 'query' and x[2] == ('reset arp dynamic', 'display arp') for x in preceding))
            previous_ping = index

    def test_preflight_guard_exception_has_no_configuration_ping_or_capture(self):
        h = self.harness()
        h.guard_error = True
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(h.applied(), [])
        self.assertEqual(h.pings(), [])
        self.assertFalse(any(x[0] in ('discover', 'query') for x in h.events))
        self.assertIn('wrong project', (runner.folder/'diagnostic.txt').read_text(encoding='utf-8'))

    def test_missing_pc_or_capture_preflight_stops_before_configuration(self):
        for attribute in ('probe_status', 'discovery_status'):
            with self.subTest(attribute=attribute):
                h = self.harness()
                setattr(h, attribute, 'needs_attention')
                runner = h.runner()
                runner.run()
                self.assertEqual(runner.record['status'], 'needs_attention')
                self.assertEqual(h.applied(), [])
                self.assertEqual(h.pings(), [])

    def test_stage_capture_checkpoint_failure_sends_no_ping(self):
        h = self.harness()
        h.fail_checkpoint = '*'
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(h.pings(), [])
        self.assertEqual(h.applied(), ['part1-default'])
        self.assertTrue(any('checkpoint missing' in x for x in runner.record['missing']))

    def test_per_ping_checkpoint_failure_sends_no_ping(self):
        h = self.harness()
        h.fail_checkpoint = '01-PC1-PC2'
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(h.pings(), [])
        self.assertTrue(any(x[0] == 'clear_pc' for x in h.events))

    def test_unverified_pc_arp_clear_stops_before_ping(self):
        h = self.harness()
        h.arp_clear = False
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(h.pings(), [])

    def test_unknown_or_partial_statistics_stop_following_stages(self):
        cases = [{'unknown': True}, {'sent': None}, {'sent': 3},
                 {'received': None}, {'status': 'incomplete'}]
        for override in cases:
            with self.subTest(override=override):
                h = self.harness()
                h.ping_override = override
                runner = h.runner()
                runner.run()
                self.assertEqual(runner.record['status'], 'needs_attention')
                self.assertEqual(len(h.pings()), 1)
                self.assertEqual(h.applied(), ['part1-default'])
                self.assertFalse(runner.record['pings'][0]['matches_expected'])
                self.assertIn('capture', runner.record['pings'][0])

    def test_timeout_never_resends_and_records_manual_stop(self):
        h = self.harness()
        h.ping_override = {'status': 'timeout', 'received': None, 'manual_stop_required': True}
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(len(h.pings()), 1)
        self.assertTrue(any('Ctrl+C' in x for x in runner.record['manual_actions']))
        self.assertTrue((runner.folder/'diagnostic.txt').exists())

    def test_timeout_manual_stop_survives_simultaneous_capture_rotation_error(self):
        h = self.harness()
        h.ping_override = {'status': 'timeout', 'received': None, 'manual_stop_required': True}
        h.export_error = True
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(len(h.pings()), 1)
        self.assertTrue(any('Ctrl+C' in x for x in runner.record['manual_actions']))
        self.assertIn('Ctrl+C', (runner.folder/'实测记录.md').read_text(encoding='utf-8'))

    def test_complete_partial_loss_keeps_actual_count_and_observation(self):
        # 完整统计的部分丢包与未知/截断输出分开处理，绝不把3/4改写为4/4。
        h = self.harness()
        runner = h.runner()
        runner.prepare()
        h.stage = 'part1-default'
        h.ping_override = {'received': 3}
        runner.ping('part1-default', 'PC1', 'PC2', True, 1)
        self.assertEqual(runner.record['pings'][0]['actual']['received'], 3)
        self.assertTrue(runner.record['pings'][0]['matches_expected'])
        self.assertTrue(any('接收3/4' in x for x in runner.record['observations']))
        self.assertEqual(len(h.pings()), 1)

    def test_unexpected_reachability_stops_at_the_isolation_stage(self):
        h = self.harness('part2')
        h.ping_override = {'received': 4}
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(h.applied(), ['part2-access'])
        self.assertEqual(len(h.pings()), 1)

    def test_missing_screenshots_keeps_evidence_pending_after_execution(self):
        h = self.harness()
        h.screenshots = False
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'evidence_pending')
        self.assertEqual(len(h.pings()), 6)
        self.assertEqual(len([x for x in runner.record['missing'] if '现场截图' in x]), 6)

    def test_missing_routed_arp_protocols_keeps_completed_traffic_evidence_pending(self):
        h = self.harness('part2')
        h.analyzer_summary = protocol_summary()
        h.analyzer_summary['arp_groups'] = []
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'evidence_pending')
        self.assertEqual(len(h.pings()), 6)
        self.assertEqual(len(runner.record['stages']), 2)
        self.assertEqual(len([x for x in runner.record['missing'] if 'ARP请求/应答' in x]), 3)
        self.assertTrue(all(x['matches_expected'] for x in runner.record['pings']))

    def test_export_rotation_exception_preserves_ping_and_halts(self):
        h = self.harness()
        h.export_error = True
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(len(h.pings()), 1)
        self.assertEqual(len(runner.record['pings']), 1)
        self.assertEqual(h.applied(), ['part1-default'])
        saved = json.loads((runner.folder/'run.json').read_text(encoding='utf-8'))
        self.assertIn('rotation failure', saved['error'])
        self.assertEqual(saved['pings'][0]['actual']['sent'], 4)

    def test_reported_capture_missing_halts_and_preserves_diagnostics(self):
        h = self.harness()
        h.capture_missing = ['TEST FIXTURE incomplete capture window']
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertIn(h.capture_missing[0], runner.record['missing'])
        self.assertEqual(len(h.pings()), 1)
        self.assertTrue((runner.folder/'capture-export-failure.json').is_file())

    def test_incomplete_capture_status_without_gap_text_still_halts(self):
        h = self.harness()
        h.export_status = 'incomplete'
        runner = h.runner()
        runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(len(h.pings()), 1)
        self.assertTrue((runner.folder/'capture-export-failure.json').is_file())

    def test_access_stage_gateway_arp_only_is_accepted_by_real_capture_validator(self):
        # S1默认时跨网段失败通常停留在网关ARP，尚未形成ICMP请求。
        from capture_workflow import CaptureSession
        h = self.harness('part2')
        runner = h.runner()
        runner.run()
        expectations = next(value for label, value in h.export_expectations
                            if label == 'part2-access-01-PC1-PC2')
        session = object.__new__(CaptureSession)
        session.hosts = runner.hosts
        evidence = {'S2-PC1': {'analysis': {'frames': [{
            'protocol': 'ARP', 'arp_opcode': 1, 'source_ip': '192.168.100.1',
            'destination_ip': '192.168.100.254', 'source_frame': 1}], 'icmp_echo_pairs': []}}}
        results, gaps = session._check_expectations(evidence, expectations)
        self.assertEqual(gaps, [], gaps)
        self.assertEqual(results[0]['status'], 'gateway_arp_without_echo_reply')

    def test_link_or_stp_not_ready_blocks_all_pings(self):
        h = self.harness('part2')
        h.query_down = True
        runner = h.runner()
        ticks = iter(range(0, 10000, 100))
        with patch.object(r.time, 'monotonic', side_effect=lambda: next(ticks)):
            runner.run()
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertEqual(h.pings(), [])
        self.assertIn('尚未发起', runner.record['error'])
        self.assertTrue(list((runner.folder/'readiness').rglob('*.txt')))

    def test_check_only_never_enrolls_clears_configures_or_pings(self):
        h = self.harness('part2')
        runner = h.runner()
        runner.interactive = True
        runner.run(check_only=True)
        self.assertEqual(runner.record['status'], 'ready_check_only')
        self.assertFalse(any(x[0] in ('enroll', 'checkpoint', 'export', 'query', 'clear_pc', 'ping', 'collect') for x in h.events))

    def test_check_only_missing_capture_never_enrolls(self):
        h = self.harness()
        h.discovery_status = 'needs_input'
        runner = h.runner()
        runner.interactive = True
        runner.run(check_only=True)
        self.assertEqual(runner.record['status'], 'needs_attention')
        self.assertFalse(any(x[0] in ('enroll', 'collect', 'ping', 'checkpoint') for x in h.events))


class EvidenceValidationTests(unittest.TestCase):
    def test_protocol_evidence_requires_both_echo_relations_and_all_three_arps(self):
        summary = protocol_summary()
        self.assertEqual(r.validate_protocol_evidence([summary]), [])
        summary['arp_groups'].pop()
        self.assertIn('跨网段S1查询PC2的ARP请求/应答', r.validate_protocol_evidence([summary]))
        summary['icmp_echo_groups'][1]['matched_pairs'] = 0
        self.assertIn('跨VLAN ICMP请求/应答', r.validate_protocol_evidence([summary]))

    def test_state_checks_each_used_port_and_routed_vlanif(self):
        physical = '\n'.join(f'Eth0/0/{p} up up 0% 0% 0 0' for p in (1, 2))
        stp = '\n'.join(f'0 Eth0/0/{p} DESI FORWARDING NONE' for p in (1, 2))
        responses = {'display interface brief': physical, 'display stp brief': stp,
            'display ip interface brief': 'Vlanif100 192.168.100.254/24 up up\nVlanif200 192.168.200.254/24 up up'}
        self.assertEqual(r.state_issues('part2', 'S1', responses, True), [])
        responses['display ip interface brief'] = responses['display ip interface brief'].replace('200.254/24 up up', '200.254/24 down down')
        self.assertTrue(any('Vlanif200' in x for x in r.state_issues('part2', 'S1', responses, True)))
        responses['display stp brief'] = stp.replace('Eth0/0/1 DESI FORWARDING', 'Eth0/0/1 DESI DISCARDING')
        self.assertTrue(any('Ethernet0/0/1 STP' in x for x in r.state_issues('part2', 'S1', responses)))


if __name__ == '__main__':
    unittest.main()
