"""供用户主动运行的助手设置 eNSP 内置 UDP 页；不依赖屏幕坐标。"""
import ctypes as C
from ctypes import wintypes as W
import re, time

WM_SETTEXT = 0x000C
WM_GETTEXT = 0x000D
BM_CLICK, BM_GETCHECK = 0x00F5, 0x00F0
IPM_SETADDRESS = 0x0400 + 101


def clean_mac(text):
    return re.sub(r'[^0-9a-f]', '', text.lower())


class PCWindows:
    def __init__(self, project, process_id, progress=None):
        self.project = project
        self.process_id = int(process_id)
        self.progress = progress or (lambda detail: None)
        self.u = C.WinDLL('user32', use_last_error=True)
        self.callback = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        self.u.GetDlgItem.argtypes = [W.HWND, C.c_int]
        self.u.GetDlgItem.restype = W.HWND
        self.u.GetParent.argtypes = [W.HWND]
        self.u.GetParent.restype = W.HWND
        self.u.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
        self.u.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
        self.u.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
        self.u.IsWindowVisible.argtypes = [W.HWND]
        self.u.IsWindowEnabled.argtypes = [W.HWND]
        self.u.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM, W.UINT, W.UINT, C.POINTER(C.c_size_t)]
        self.u.SendMessageTimeoutW.restype = W.LPARAM
        self.u.EnumWindows.argtypes = [self.callback, W.LPARAM]
        self.u.EnumChildWindows.argtypes = [W.HWND, self.callback, W.LPARAM]

    def send(self, hwnd, msg, wp=0, lp=0):
        result = C.c_size_t()
        if not self.u.SendMessageTimeoutW(hwnd, msg, wp, lp, 2, 3000, C.byref(result)):
            raise RuntimeError('窗口未响应或权限不足；请以管理员身份运行入口。')
        return result.value

    def title(self, hwnd):
        b = C.create_unicode_buffer(2048)
        self.u.GetWindowTextW(hwnd, b, len(b))
        return b.value

    def text(self, hwnd):
        b = C.create_unicode_buffer(2048)
        self.send(hwnd, WM_GETTEXT, len(b), C.addressof(b))
        return b.value

    def children(self, parent=0):
        rows = []
        cb = self.callback(lambda h, _: rows.append(h) or True)
        if parent:
            self.u.EnumChildWindows(parent, cb, 0)
        else:
            self.u.EnumWindows(cb, 0)
        return rows

    def control(self, dialog, ident):
        h = self.u.GetDlgItem(dialog, ident)
        if not h:
            raise RuntimeError(f'UDP 页面缺少控件 {ident}，停止发送。')
        return h

    def find(self, name, expected_mac):
        self.progress(f'{name}：定位 UDP 页面并核对源 MAC')
        # 本机主窗口标题仅为 eNSP_Client；用新副本三个 Console 的进程归属限定。
        # 调用方已核对独立设备 UUID 的运行资源与三个 Console 均已就绪。
        roots=[]
        for h in self.children():
            pid=W.DWORD();self.u.GetWindowThreadProcessId(h,C.byref(pid))
            if pid.value==self.process_id:roots.append(h)
        if not roots:raise RuntimeError('未找到新副本 Console 所属的 eNSP 窗口。')
        windows=[]
        for root in roots:windows += [root] + self.children(root)
        windows = list(dict.fromkeys(windows))
        candidates = []
        for pc in windows:
            title = self.title(pc).strip()
            if title not in (name, 'PC-' + name, 'PC ' + name):
                continue
            for d in [pc] + self.children(pc):
                if all(self.u.GetDlgItem(d, i) for i in [1095, 1096, 1114, 1008, 1009, 1148]):
                    if self.u.IsWindowVisible(d):
                        candidates.append(d)
        candidates = list(dict.fromkeys(candidates))
        if len(candidates) != 1:
            raise RuntimeError(f'请打开 {name} 的“UDP发包工具”页并保持打开；当前找到 {len(candidates)} 个可见页面。')
        dialog = candidates[0]
        current = self.text(self.control(dialog, 1096))
        if clean_mac(current) != clean_mac(expected_mac):
            raise RuntimeError(f'{name} 源 MAC 与工程不符，停止：{current}')
        return dialog

    def set_text(self, dialog, ident, value):
        buf = C.create_unicode_buffer(str(value))
        self.send(self.control(dialog, ident), WM_SETTEXT, 0, C.addressof(buf))
        if self.text(self.control(dialog, ident)).strip() != str(value):
            raise RuntimeError(f'字段 {ident} 写入后回读不一致。')

    def check(self, dialog, ident, value):
        h = self.control(dialog, ident)
        if bool(self.send(h, BM_GETCHECK)) != bool(value):
            self.send(h, BM_CLICK)
        if bool(self.send(h, BM_GETCHECK)) != bool(value):
            raise RuntimeError(f'选项 {ident} 回读失败。')

    def prepare(self, dialog, source, destination, step):
        self.progress('设置 IPv4、关闭 VLAN 和周期发送')
        self.check(dialog, 1089, True)
        self.check(dialog, 1100, False)
        self.check(dialog, 1024, False)
        self.progress('填写并回读源 MAC')
        self.set_text(dialog, 1096, source['mac'])
        self.progress('填写并回读目的 MAC')
        self.set_text(dialog, 1095, destination['mac'])
        for ident, ip in [(1094, source['ip']), (1093, destination['ip'])]:
            self.progress('填写并回读 IP：' + ip)
            value = int.from_bytes(bytes(map(int, ip.split('.'))), 'big')
            self.send(self.control(dialog, ident), IPM_SETADDRESS, 0, value)
            if self.text(self.control(dialog, ident)).replace(' ', '') != ip:
                raise RuntimeError(f'IP 字段 {ident} 回读失败。')
        for ident, value in [(1117, '1'), (1118, '1'), (1116, '1500'), (1008, f'{step:02x}'), (1114, '29')]:
            label = {1117:'源端口',1118:'目的端口',1116:'MTU',1008:'十六进制数据',1114:'数据包长度'}[ident]
            self.progress(f'填写并回读{label}：{value}')
            self.set_text(dialog, ident, value)
        return self.count(dialog)

    def count(self, dialog):
        value = self.text(self.control(dialog, 1148)).strip()
        if not value.isdigit():
            raise RuntimeError('发送计数读取失败，停止以避免重复发包。')
        return int(value)

    def send_once(self, dialog, expected_before=None):
        self.progress('核对发送计数，随后只点击一次发送')
        before = self.count(dialog)
        if expected_before is not None and before!=expected_before:
            raise RuntimeError(f'发送计数在准备后改变：本轮起点{expected_before}，当前{before}；已停止，尚未点击本步发送。')
        button = self.control(dialog, 1009)
        if not self.u.IsWindowEnabled(button):
            raise RuntimeError('发送按钮不可用。')
        self.send(button, BM_CLICK)
        self.progress('已点击一次发送，等待计数增加（最多3秒）')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            after=self.count(dialog)
            if after==before+1:
                self.progress(f'本轮发送计数核对通过：{before}→{after}（只增加1）')
                return after
            if after<before or after>before+1:
                raise RuntimeError(f'发送计数异常：{before}→{after}，本步应只增加1；不自动重试。')
            time.sleep(.1)
        raise RuntimeError('发送计数未增加；已停止，不自动重试。')
