"""验证证据归档及决策记录；全部使用临时测试文件。"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import assistant


class AssistantTests(unittest.TestCase):
    def test_evidence_preserves_source_and_unique_archives(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            source = root/'ping.txt'
            source.write_text('TEST FIXTURE ping output', encoding='utf-8')
            before = source.read_bytes()
            with patch.object(assistant, 'ROOT', root):
                first = assistant.import_evidence('part2-routing', 'ping', source, '测试夹具')
                second = assistant.import_evidence('part2-routing', 'ping', source, '测试夹具')
            self.assertNotEqual(first, second)
            self.assertEqual((first/'original.txt').read_bytes(), before)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(json.loads((first/'manifest.json').read_text(encoding='utf-8'))['review_status'], '已归档，内容待核对')

    def test_empty_and_wrong_type_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root/'empty.txt'
            source.touch()
            with patch.object(assistant, 'ROOT', root):
                with self.assertRaises(ValueError):
                    assistant.import_evidence('part1-default', 'ping', source, '测试夹具')
                source.write_text('fixture', encoding='utf-8')
                with self.assertRaises(ValueError):
                    assistant.import_evidence('part1-default', 'capture', source, '测试夹具')
            self.assertFalse((root/'local'/'evidence').exists())

    def test_confirmation_stays_local_and_records_real_source(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            with patch.object(assistant, 'ROOT', root):
                assistant.confirm_ports('TEST FIXTURE user confirmation')
            info = json.loads((root/'local'/'state'/'decisions.json').read_text(encoding='utf-8'))
            self.assertEqual(info['port_range']['source'], 'user')
            self.assertEqual(info['port_range']['interface'], 'Ethernet')
            self.assertFalse((root/'AGENTS.md').exists())
            self.assertEqual(len(list((root/'local'/'state'/'decision-history').glob('*.json'))), 1)

    def test_blank_confirmation_has_no_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(assistant, 'ROOT', Path(tmp)):
            with self.assertRaises(ValueError):
                assistant.confirm_ports(' ')
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
