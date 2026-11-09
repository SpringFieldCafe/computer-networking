"""验证五步完整表、过滤、MAC 迁移、老化刷新和 VLAN 隔离。"""
import unittest
from switch_model import Switch, run, model_frame, checksum


class LearningTests(unittest.TestCase):
    def test_five_steps(self):
        result, frames = run()
        expected = [
            [{'C1': 1}, {'C1': 1}, {'C1': 1}],
            [{'C1': 1, 'C2': 3}, {'C1': 1, 'C2': 1}, {'C1': 1, 'C2': 1}],
            [{'C1': 1, 'C2': 3, 'C3': 2}, {'C1': 1, 'C2': 1, 'C3': 3}, {'C1': 1, 'C2': 1, 'C3': 1}],
            [{'C1': 1, 'C2': 3, 'C3': 2}, {'C1': 1, 'C2': 1, 'C3': 3, 'C4': 2}, {'C1': 1, 'C2': 1, 'C3': 1, 'C4': 3}],
            [{'C1': 1, 'C2': 3, 'C3': 2}, {'C1': 1, 'C2': 1, 'C3': 3, 'C4': 2}, {'C1': 1, 'C2': 1, 'C3': 1, 'C4': 3, 'C5': 2}],
        ]
        for step, tables in zip(result['steps'], expected):
            self.assertEqual(list(step['tables'].values()), tables)
        self.assertEqual([sum(f[0] == i for f in frames) for i in range(1, 6)], [7, 7, 7, 3, 2])
        self.assertEqual([e['switch'] for e in result['steps'][3]['events']], ['SW3', 'SW2'])
        self.assertEqual([e['switch'] for e in result['steps'][4]['events']], ['SW3'])

    def test_filter_and_movement(self):
        s = Switch()
        self.assertEqual(s.receive('A', 'B', 1, 0), ('新增', '泛洪', [2, 3]))
        self.assertEqual(s.receive('B', 'A', 1, 1), ('新增', '过滤', []))
        self.assertEqual(s.receive('A', 'B', 2, 2), ('迁移', '单播', [1]))
        self.assertEqual(s.snapshot(), {'A': 2, 'B': 1})

    def test_aging_refresh(self):
        s = Switch(aging=10)
        s.receive('A', 'B', 1, 0)
        s.receive('A', 'B', 1, 9)
        s.expire(10)
        self.assertIn((1, 'A'), s.table)
        s.expire(19)
        self.assertEqual(s.table, {})

    def test_disabled_aging(self):
        s = Switch(aging=0)
        s.receive('A', 'B', 1, 0)
        s.expire(1000000)
        self.assertEqual(s.snapshot(), {'A': 1})

    def test_vlan_isolation(self):
        s = Switch()
        s.receive('A', 'B', 1, 0, vlan=1)
        self.assertEqual(s.receive('B', 'A', 2, 1, vlan=2)[1:], ('泛洪', [1, 3]))

    def test_packet_headers(self):
        frame = model_frame(1, 5, 1)
        self.assertEqual(frame[:6], bytes.fromhex('020000000005'))
        self.assertEqual(checksum(frame[14:34]), 0)
        self.assertIn(b'MODEL CNEXP2 STEP1', frame)


if __name__ == '__main__':
    unittest.main()
