"""重启助手的回归测试；PCAP为临时测试夹具，不是实验记录。"""
from pathlib import Path
from unittest.mock import Mock, patch
import hashlib
import importlib.util
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from capture_sessions import active_paths,checkpoint,export_window,_image_process_ids
from pc_windows import PCWindows,BM_CLICK
spec=importlib.util.spec_from_file_location('retry_helper',ROOT/'实验助手.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


def header(endian='<'):
    return struct.pack(endian+'IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)


def record(payload,number=1,endian='<'):
    # 保留可逐字节对照的合成测试记录，不写入任何实验目录。
    frame=b'\xff'*6+b'\x02\0\0\0\0\x01'+b'\x08\x06'+payload
    return struct.pack(endian+'IIII',1700000000+number,123456,len(frame),len(frame))+frame


class CaptureRetryTests(unittest.TestCase):
    def test_native_process_reader_finds_this_python_process(self):
        self.assertIn(os.getpid(),_image_process_ids(Path(sys.executable).name))

    def test_preopened_running_files_are_recognized(self):
        files={Path(f'wiresharkXXXXa{p}') for p in range(100,107)}
        self.assertEqual(active_paths(files,pids=range(100,107)),files)

    def test_stopped_old_files_are_excluded(self):
        files={Path('wiresharkXXXXa10'),Path('wiresharkXXXXa20'),Path('unrelated.pcap')}
        self.assertEqual(active_paths(files,pids={20}),{Path('wiresharkXXXXa20')})

    def test_only_this_round_bytes_are_exported_and_raw_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'wiresharkXXXXa10';out=Path(td)/'window.pcap'
            first=header()+record(b'OLD-TEST-FIXTURE',1)
            source.write_bytes(first)
            selection=checkpoint({source},helper.read_manifest())[0]
            self.assertEqual(selection['start_frame'],1)
            second=record(b'NEW-TEST-FIXTURE',2)
            source.write_bytes(first+second)
            before=hashlib.sha256(source.read_bytes()).digest()
            self.assertEqual(export_window(source,out,selection),1)
            self.assertEqual(out.read_bytes(),header()+second)
            self.assertEqual(hashlib.sha256(source.read_bytes()).digest(),before)

    def test_big_endian_capture_window(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'wiresharkXXXXa10';out=Path(td)/'window.pcap'
            first=header('>')+record(b'OLD',1,'>');source.write_bytes(first)
            selection=checkpoint({source},helper.read_manifest())[0]
            second=record(b'NEW',2,'>');source.write_bytes(first+second)
            export_window(source,out,selection)
            self.assertEqual(out.read_bytes(),header('>')+second)

    def test_truncation_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'wiresharkXXXXa10';out=Path(td)/'window.pcap'
            source.write_bytes(header()+record(b'OLD',1))
            selection=checkpoint({source},helper.read_manifest())[0]
            source.write_bytes(header())
            with self.assertRaisesRegex(ValueError,'替换或截断'):export_window(source,out,selection)
            self.assertFalse(out.exists())

    def test_import_uses_selected_files_after_capture_process_stops(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'wiresharkXXXXa10'
            first=header()+record(b'OLD',1);source.write_bytes(first)
            selection=checkpoint({source},helper.read_manifest())
            second=record(b'NEW',2);source.write_bytes(first+second)
            dest=Path(td)/'saved';dest.mkdir()
            with patch.object(helper,'temp_pcaps',side_effect=AssertionError('不应重新发现文件')):
                captures,issues=helper.import_captures(dest,selection,helper.read_manifest())
            self.assertEqual(len(captures),1)
            self.assertEqual(Path(captures[0]['file']).read_bytes(),header()+second)
            self.assertEqual(Path(captures[0]['raw_file']).read_bytes(),first+second)
            self.assertEqual(captures[0]['excluded_previous_frames'],1)


class SendCounterTests(unittest.TestCase):
    def sender(self,counts):
        # 只替换控件访问，不创建或操作真实窗口。
        ui=PCWindows.__new__(PCWindows)
        ui.count=Mock(side_effect=counts)
        ui.control=Mock(return_value=999)
        ui.send=Mock()
        ui.progress=Mock()
        ui.u=Mock();ui.u.IsWindowEnabled.return_value=True
        return ui

    def test_nonzero_prior_count_sends_once(self):
        ui=self.sender([7,8])
        self.assertEqual(ui.send_once(123,expected_before=7),8)
        ui.send.assert_called_once_with(999,BM_CLICK)

    def test_zero_prior_count_still_sends_once(self):
        ui=self.sender([0,1])
        self.assertEqual(ui.send_once(123,expected_before=0),1)
        ui.send.assert_called_once_with(999,BM_CLICK)

    def test_counter_changed_before_send_is_rejected_without_click(self):
        ui=self.sender([8])
        with self.assertRaisesRegex(RuntimeError,'准备后改变'):ui.send_once(123,expected_before=7)
        ui.send.assert_not_called()

    def test_double_increment_is_rejected_without_retry(self):
        ui=self.sender([7,9])
        with self.assertRaisesRegex(RuntimeError,'应只增加1'):ui.send_once(123,expected_before=7)
        ui.send.assert_called_once_with(999,BM_CLICK)

    def test_counter_reset_is_rejected_without_retry(self):
        ui=self.sender([7,0])
        with self.assertRaisesRegex(RuntimeError,'计数异常'):ui.send_once(123,expected_before=7)
        ui.send.assert_called_once_with(999,BM_CLICK)

    def test_timeout_does_not_click_again(self):
        ui=self.sender([7,7])
        with patch('pc_windows.time.monotonic',side_effect=[0,.1,4]),patch('pc_windows.time.sleep'):
            with self.assertRaisesRegex(RuntimeError,'不自动重试'):ui.send_once(123,expected_before=7)
        ui.send.assert_called_once_with(999,BM_CLICK)


if __name__=='__main__':unittest.main()
