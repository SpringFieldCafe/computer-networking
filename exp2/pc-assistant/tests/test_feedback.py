"""反馈与抓包前置检查回归；不连接真实设备，不设置用户窗口。"""
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
import importlib.util
import io
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('easy_helper_feedback',ROOT/'实验助手.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
from console_status import Activity,confirm,session_log
import pc_windows


class FeedbackTests(unittest.TestCase):
    def test_missing_captures_block_gui_and_device_changes(self):
        manifest=helper.read_manifest()
        with patch.object(helper,'confirm',side_effect=[None,KeyboardInterrupt]), \
             patch.object(helper,'live_captures',return_value=set()), \
             patch.object(helper,'wait_ready',return_value=123), \
             patch.object(pc_windows,'PCWindows') as windows, \
             patch.object(helper,'collect') as collect,redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(KeyboardInterrupt):helper.run(manifest)
        windows.assert_not_called();collect.assert_not_called()
        self.assertIn('0/7',output.getvalue())
        self.assertIn('右键',output.getvalue())

    def test_six_active_captures_are_insufficient(self):
        active={Path(f'active{i}') for i in range(6)}
        with patch.object(helper,'live_captures',return_value=active), \
             patch.object(helper,'confirm',side_effect=KeyboardInterrupt),redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(KeyboardInterrupt):helper.require_captures()
        self.assertIn('6/7',out.getvalue())

    def test_exactly_seven_new_captures_can_continue(self):
        with patch.object(helper,'live_captures',return_value={Path(str(i)) for i in range(7)}), \
             patch.object(helper,'confirm') as question,redirect_stdout(io.StringIO()):
            helper.require_captures()
        question.assert_not_called()

    def test_duplicate_capture_preparation_is_blocked(self):
        with patch.object(helper,'live_captures',return_value={Path(str(i)) for i in range(8)}), \
             patch.object(helper,'confirm',side_effect=KeyboardInterrupt),redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(KeyboardInterrupt):helper.require_captures()
        self.assertIn('多余抓包',out.getvalue())

    def test_device_timeout_reports_all_missing_switches(self):
        with tempfile.TemporaryDirectory() as td,patch.dict(helper.os.environ,{'LOCALAPPDATA':td}),redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError) as caught:helper.wait_ready(helper.read_manifest(),timeout=.01)
        for name in ['SW1','SW2','SW3']:self.assertIn(name,str(caught.exception))
        self.assertIn('尚未清表或发包',str(caught.exception))

    def test_console_owner_query_has_deadline(self):
        m=helper.read_manifest()
        with tempfile.TemporaryDirectory() as td:
            for v in m['switches'].values():
                cfg=Path(td)/'eNSP/VBoxServer/workspaces'/v['id']/'slot17/hardcfg.tcl'
                cfg.parent.mkdir(parents=True);cfg.write_text('SetDeviceID '+v['id'])
            with patch.dict(helper.os.environ,{'LOCALAPPDATA':td}), \
                 patch.object(helper.socket,'create_connection'), \
                 patch.object(helper.subprocess,'run',side_effect=subprocess.TimeoutExpired('powershell',15)) as run, \
                 redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,'超过15秒'):helper.wait_ready(m)
        self.assertEqual(run.call_args.kwargs['timeout'],15)

    def test_progress_does_not_invent_completion(self):
        with redirect_stdout(io.StringIO()) as out:
            with Activity('检查实际数量',total=3,interval=.01) as activity:
                activity.update('只完成一项',1,3);time.sleep(.025)
        text=out.getvalue()
        self.assertIn('1/3',text);self.assertNotIn('3/3',text)
        self.assertGreaterEqual(text.count('秒'),3)

    def test_failed_activity_is_marked_stopped(self):
        with redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(ValueError):
                with Activity('失败示例'):raise ValueError('test')
        self.assertIn('[已停止]',out.getvalue());self.assertNotIn('[已完成]',out.getvalue())

    def test_confirmation_accepts_one_fresh_enter(self):
        with patch('sys.stdin.isatty',return_value=True), \
             patch('msvcrt.kbhit',side_effect=[False,True]), \
             patch('msvcrt.getwch',return_value='\r') as key,redirect_stdout(io.StringIO()) as out:
            confirm('人工确认')
        key.assert_called_once();self.assertIn('[已收到确认]',out.getvalue())

    def test_stale_enter_cannot_confirm_new_stage(self):
        with patch('sys.stdin.isatty',return_value=True), \
             patch('msvcrt.kbhit',side_effect=[True,False,True]), \
             patch('msvcrt.getwch',side_effect=['\r','q']),redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(KeyboardInterrupt):confirm('人工确认')
        self.assertNotIn('[已收到确认]',out.getvalue())

    def test_python_output_is_saved_and_restored(self):
        with tempfile.TemporaryDirectory() as td,redirect_stdout(io.StringIO()) as original:
            with session_log(td) as path:
                print('测试阶段反馈')
            self.assertIs(sys.stdout,original)
            self.assertIn('测试阶段反馈',path.read_text(encoding='utf-8'))

    def test_console_timeout_keeps_bytes_and_reports_wait(self):
        class SilentConsole:
            first=True
            def recv(self,size):
                if self.first:self.first=False;return b'partial'
                time.sleep(.002);raise socket.timeout()
        updates=[]
        from collect_switches import read_prompt,ConsoleReadError
        with self.assertRaises(ConsoleReadError) as caught:
            read_prompt(SilentConsole(),timeout=.01,progress=updates.append)
        self.assertEqual(caught.exception.output,'partial')
        self.assertTrue(any('7 字节' in s for s in updates))


if __name__=='__main__':unittest.main()
