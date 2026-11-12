"""权限入口测试：不实际弹UAC、不打开菜单或窗口。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import launch_assistant as launch


class LaunchTests(unittest.TestCase):
    def test_only_matching_real_target_elevation_requests_uac(self):
        self.assertTrue(launch.needs_elevation(False, [True]))
        self.assertFalse(launch.needs_elevation(False, [False]))
        self.assertFalse(launch.needs_elevation(False, []))
        self.assertFalse(launch.needs_elevation(False, [None]))
        self.assertFalse(launch.needs_elevation(True, [True]))

    def test_matching_privileges_start_menu_without_elevation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(launch, 'ROOT', Path(tmp)), \
                patch.object(launch, 'process_elevated', return_value=True), \
                patch.object(launch, 'ensp_pids', return_value=[123]), \
                patch.object(launch.subprocess, 'call', return_value=0) as call:
            self.assertEqual(launch.main([]), 0)
            self.assertEqual(call.call_args.args[0][-1], 'menu')
            self.assertEqual(len(list((Path(tmp)/'local'/'launch').glob('*.json'))), 1)
