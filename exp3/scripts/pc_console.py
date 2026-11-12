"""eNSP 内置 PC 命令页的后台消息接口；用户打开工程/命令页后主动运行。

只识别 eNSP_Client 所属 PC 对话框内 ID=1084 的 RichEdit20A，绝不调用系统
ping。不切换页、不启动设备、不抢焦点、不注入全局键盘事件。原始文本与实窗
PrintWindow 截图只写 exp3/local。支持情况见 local/automation-research。
"""
from datetime import datetime
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
from ipaddress import IPv4Address
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / 'local'
WM_GETTEXT, WM_GETTEXTLENGTH, WM_CHAR, EM_SETSEL = 0xD, 0xE, 0x102, 0xB1
COMMAND_CONTROL_ID = 1084
MAX_TEXT = 1_048_576
PROMPT = re.compile(r'(?:^|[\r\n])PC>\s*\Z')
IP_RE = r'(?:\d{1,3}\.){3}\d{1,3}'
MAC_RE = r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'


def stamp():
    return datetime.now().astimezone().isoformat()


def clean_mac(value):
    return re.sub(r'[-:.]', '', str(value)).lower()


def local_directory(value=None):
    path = Path(value) if value is not None else LOCAL / 'pc-records'
    path = path.resolve()
    if not path.is_relative_to(LOCAL.resolve()):
        raise ValueError('PC 原始输出与截图必须位于 exp3/local 内')
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(frozen=True)
class Window:
    hwnd: int
    parent: int
    pid: int
    title: str
    class_name: str
    control_id: int
    visible: bool
    enabled: bool


class PCConsoleError(RuntimeError):
    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result or {}


class Win32Native:
    """所有指针/句柄使用指针宽度。WM_GETTEXT 由 Windows 跨进程封送。

    不把自定义 RichEdit 消息中含指针的结构传入外进程。SendMessageTimeoutW
    统一 1500ms 上限；PrintWindow 放入有超时的独立 Python 子进程。
    """
    def __init__(self, process_id):
        if sys.platform != 'win32':
            raise PCConsoleError('实机后台接口需要 Windows；模拟测试可跨平台运行')
        self.pid = int(process_id)
        self.u = C.WinDLL('user32', use_last_error=True)
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.callback_type = C.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        signatures = {
            'SendMessageTimeoutW': ([W.HWND, W.UINT, W.WPARAM, W.LPARAM,
                                    W.UINT, W.UINT, C.POINTER(C.c_size_t)], C.c_ssize_t),
            'GetWindowTextW': ([W.HWND, W.LPWSTR, C.c_int], C.c_int),
            'GetClassNameW': ([W.HWND, W.LPWSTR, C.c_int], C.c_int),
            'GetWindowThreadProcessId': ([W.HWND, C.POINTER(W.DWORD)], W.DWORD),
            'GetParent': ([W.HWND], W.HWND),
            'GetDlgCtrlID': ([W.HWND], C.c_int),
            'IsWindowVisible': ([W.HWND], W.BOOL),
            'IsWindowEnabled': ([W.HWND], W.BOOL),
            'IsWindow': ([W.HWND], W.BOOL),
            'GetAsyncKeyState': ([C.c_int], C.c_short),
            'EnumWindows': ([self.callback_type, W.LPARAM], W.BOOL),
            'EnumChildWindows': ([W.HWND, self.callback_type, W.LPARAM], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            func = getattr(self.u, name)
            func.argtypes, func.restype = args, result
        self.k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
        self.k.OpenProcess.restype = W.HANDLE
        self.k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
        self.k.QueryFullProcessImageNameW.restype = W.BOOL
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.k.CloseHandle.restype = W.BOOL

    def process_image(self):
        handle = self.k.OpenProcess(0x1000, False, self.pid)
        if not handle:
            raise PCConsoleError('无法查询 eNSP 进程身份，请核对权限与进程号')
        try:
            text = C.create_unicode_buffer(32768)
            size = W.DWORD(len(text))
            if not self.k.QueryFullProcessImageNameW(handle, 0, text, C.byref(size)):
                raise PCConsoleError('eNSP 进程路径回读失败')
            return text.value
        finally:
            self.k.CloseHandle(handle)

    def pid_of(self, hwnd):
        pid = W.DWORD()
        self.u.GetWindowThreadProcessId(hwnd, C.byref(pid))
        return pid.value

    def send(self, hwnd, msg, wp=0, lp=0):
        if not self.u.IsWindow(hwnd) or self.pid_of(hwnd) != self.pid:
            raise PCConsoleError('窗口已关闭或句柄归属改变，停止命令')
        result = C.c_size_t()
        # SMTO_ABORTIFHUNG | SMTO_BLOCK；不使用 NOTIMEOUTIFNOTHUNG。
        C.set_last_error(0)
        if not self.u.SendMessageTimeoutW(hwnd, msg, wp, lp, 3, 1500, C.byref(result)):
            error = C.get_last_error()
            hint = '请用“启动助手.cmd”匹配eNSP权限' if error == 5 else '请核对PC已启动并打开所需页面'
            raise PCConsoleError(f'eNSP 控件消息失败（Windows错误{error}）；{hint}；本轮不重试')
        return result.value

    def text(self, hwnd):
        length = self.send(hwnd, WM_GETTEXTLENGTH)
        if length >= MAX_TEXT:
            raise PCConsoleError('命令页历史文本过长，请手动清空页面后重开助手')
        # Unicode WM_GETTEXT 到 ANSI RichEdit 由系统转换。额外容量允许轮询间追加。
        capacity = min(MAX_TEXT, max(4096, length * 2 + 4096))
        buffer = C.create_unicode_buffer(capacity)
        count = self.send(hwnd, WM_GETTEXT, capacity, C.addressof(buffer))
        if count >= capacity - 1:
            raise PCConsoleError('命令输出读取被截断，停止以免误用历史输出')
        return buffer.value

    def windows(self):
        roots, handles = [], []
        cb = self.callback_type(lambda hwnd, _: roots.append(int(hwnd)) or True)
        if not self.u.EnumWindows(cb, 0):
            raise PCConsoleError('枚举 eNSP 窗口失败')
        for root in roots:
            if self.pid_of(root) != self.pid:
                continue
            handles.append(root)
            child_cb = self.callback_type(lambda hwnd, _: handles.append(int(hwnd)) or True)
            self.u.EnumChildWindows(root, child_cb, 0)
        rows = []
        for hwnd in dict.fromkeys(handles):
            if self.pid_of(hwnd) != self.pid:
                continue
            title, cls = C.create_unicode_buffer(512), C.create_unicode_buffer(128)
            self.u.GetWindowTextW(hwnd, title, len(title))
            self.u.GetClassNameW(hwnd, cls, len(cls))
            rows.append(Window(hwnd, int(self.u.GetParent(hwnd) or 0), self.pid,
                               title.value, cls.value, self.u.GetDlgCtrlID(hwnd),
                               bool(self.u.IsWindowVisible(hwnd)), bool(self.u.IsWindowEnabled(hwnd))))
        return rows

    def submit(self, hwnd, command, before):
        # WM_CHAR 走原生 CCmdEdit 的命令缓存；WM_SETTEXT/EM_REPLACESEL 只改屏幕，
        # 不保证内部命令缓存同步，因此不使用。逐字符回读后才按 Enter。
        # 本机 DLL 的 OnChar(0x10001cf0)直接处理普通字符与 Enter，无需先发
        # WM_KEYDOWN；它先核 engine+0x188（StartSimTool 置1，Stop置0）。
        # 未启动的原生 PC 会忽略字符；FakeNative 通过不代表实机执行成功。
        self.send(hwnd, EM_SETSEL, -1, -1)
        for char in command:
            if any(self.u.GetAsyncKeyState(key) & 0x8000 for key in (0x10, 0x11, 0x12)):
                raise PCConsoleError('用户正按住 Shift/Ctrl/Alt；停止后台输入，请手动检查待输入行', {'enter_sent': False})
            self.send(hwnd, WM_CHAR, ord(char), 1)
        if self.text(hwnd) != before + command:
            raise PCConsoleError('命令输入回读不一致；尚未自动按 Enter，请确认本工程 PC 已启动，必要时打开命令页', {'enter_sent': False})
        self.send(hwnd, WM_CHAR, 13, 1)

    def interrupt(self, hwnd):
        # 不修改全局/目标线程键态。安装 DLL 的 Ctrl+C 实现同时检查 GetKeyState，
        # 因此本消息只算一次取消尝试，调用方必须回读提示符确认停止。
        self.send(hwnd, WM_CHAR, 3, 1)

    def screenshot(self, hwnd, destination):
        try:
            result = subprocess.run([sys.executable, '-X', 'utf8', str(Path(__file__).resolve()),
                                     '--print-window-worker', str(hwnd), str(self.pid), str(destination)],
                                    capture_output=True, timeout=7, check=False)
        except subprocess.TimeoutExpired:
            return {'path': None, 'missing': 'PrintWindow 超时，待用户现场截图'}
        if result.returncode != 0 or not destination.is_file():
            detail = result.stderr.decode('utf-8', errors='replace').strip()[-300:]
            return {'path': None, 'missing': '实窗截图失败，待用户现场截图' + (': ' + detail if detail else '')}
        return {'path': str(destination), 'missing': None}


def _write_png(path, width, height, bgra):
    """将 PrintWindow 的真实 DIB 像素编码为 PNG，不生成替代画面。"""
    rgb_rows = []
    colors = set()
    for y in range(height):
        line = bgra[y * width * 4:(y + 1) * width * 4]
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rgb_rows.append(b'\0' + rgb)
        if len(colors) < 3:
            colors.update(zip(rgb[0::3], rgb[1::3], rgb[2::3]))
    if len(colors) < 2:
        raise PCConsoleError('PrintWindow 返回空白或单色画面')
    def chunk(kind, payload):
        return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload) & 0xffffffff)
    data = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b''.join(rgb_rows))) + chunk(b'IEND', b''))
    with path.open('xb') as stream:
        stream.write(data)


def _print_window_worker(hwnd, pid, destination):
    path = Path(destination).resolve()
    local_directory(path.parent)
    n = Win32Native(pid)
    if Path(n.process_image()).name.lower() != 'ensp_client.exe' or n.pid_of(hwnd) != pid:
        raise PCConsoleError('截图窗口归属不符')
    u, g = n.u, C.WinDLL('gdi32', use_last_error=True)
    u.IsIconic.argtypes, u.IsIconic.restype = [W.HWND], W.BOOL
    u.GetWindowRect.argtypes, u.GetWindowRect.restype = [W.HWND, C.POINTER(W.RECT)], W.BOOL
    u.PrintWindow.argtypes, u.PrintWindow.restype = [W.HWND, W.HDC, W.UINT], W.BOOL
    if u.IsIconic(hwnd):
        raise PCConsoleError('PC 命令控件最小化，待用户恢复后截图')
    rect = W.RECT()
    if not u.GetWindowRect(hwnd, C.byref(rect)):
        raise PCConsoleError('读取截图尺寸失败')
    width, height = rect.right - rect.left, rect.bottom - rect.top
    if not (100 <= width <= 8192 and 100 <= height <= 8192):
        raise PCConsoleError('截图尺寸异常')
    class Header(C.Structure):
        _fields_ = [('size', W.DWORD), ('width', W.LONG), ('height', W.LONG),
                    ('planes', W.WORD), ('bits', W.WORD), ('compression', W.DWORD),
                    ('image', W.DWORD), ('x', W.LONG), ('y', W.LONG),
                    ('used', W.DWORD), ('important', W.DWORD)]
    g.CreateCompatibleDC.argtypes, g.CreateCompatibleDC.restype = [W.HDC], W.HDC
    g.CreateDIBSection.argtypes = [W.HDC, C.POINTER(Header), W.UINT, C.POINTER(C.c_void_p), W.HANDLE, W.DWORD]
    g.CreateDIBSection.restype = W.HBITMAP
    g.SelectObject.argtypes, g.SelectObject.restype = [W.HDC, W.HANDLE], W.HANDLE
    g.DeleteObject.argtypes, g.DeleteObject.restype = [W.HANDLE], W.BOOL
    g.DeleteDC.argtypes, g.DeleteDC.restype = [W.HDC], W.BOOL
    dc = g.CreateCompatibleDC(None)
    bitmap = old = None
    try:
        if not dc:
            raise PCConsoleError('创建截图 DC 失败')
        header = Header(C.sizeof(Header), width, -height, 1, 32, 0, width * height * 4, 0, 0, 0, 0)
        bits = C.c_void_p()
        bitmap = g.CreateDIBSection(dc, C.byref(header), 0, C.byref(bits), None, 0)
        if not bitmap or not bits:
            raise PCConsoleError('创建截图位图失败')
        old = g.SelectObject(dc, bitmap)
        if not u.PrintWindow(hwnd, dc, 2):
            raise PCConsoleError('PrintWindow 未返回有效画面')
        _write_png(path, width, height, C.string_at(bits, width * height * 4))
    finally:
        if old:
            g.SelectObject(dc, old)
        if bitmap:
            g.DeleteObject(bitmap)
        if dc:
            g.DeleteDC(dc)


def parse_ipconfig(text, expected):
    ip = re.search(r'(?im)^\s*IPv4\s+address\.*\s*:\s*(' + IP_RE + r')\s*$', text)
    mac = re.search(r'(?im)^\s*Physical\s+address\.*\s*:\s*(' + MAC_RE + r')\s*$', text)
    mask = re.search(r'(?im)^\s*Subnet\s+mask\.*\s*:\s*(' + IP_RE + r')\s*$', text)
    gateway = re.search(r'(?im)^[ \t]*Gateway\.*[ \t]*:[ \t]*([^\r\n]*)', text)
    observed_gateway = gateway[1].strip() if gateway else None
    expected_gateway = expected.get('gateway') or '0.0.0.0'
    gateway_ok = (observed_gateway.lower() in ('', '0.0.0.0', 'none', 'n/a', '-') if gateway and expected_gateway == '0.0.0.0'
                  else observed_gateway == expected_gateway)
    return {'observed_ip': ip[1] if ip else None, 'observed_mac': mac[1] if mac else None,
            'observed_mask': mask[1] if mask else None, 'observed_gateway': observed_gateway,
            'verified_ip': bool(ip and ip[1] == expected['ip']),
            'verified_mac': bool(mac and clean_mac(mac[1]) == clean_mac(expected['mac'])),
            'verified_mask': bool(mask and mask[1] == expected['mask'] == '255.255.255.0'),
            'verified_gateway': bool(gateway and gateway_ok)}


def parse_ping(text, target_ip, requested_count):
    """只解析本轮命令之后的原始增量。缺统计时保留未知，不把超时猜成四丢。"""
    # 本机 SimPC DLL 的四种统计格式均为独立的 transmitted/received 行，
    # 行尾无句点；与 Windows 系统 ping 的统计格式不同。依据保存在 local。
    transmitted = re.findall(r'(?im)^\s*(\d+)\s+packet\(s\)\s+transmitted\s*$', text)
    received = re.findall(r'(?im)^\s*(\d+)\s+packet\(s\)\s+received\s*$', text)
    sent, recv = (int(transmitted[0]) if len(transmitted) == 1 else None,
                  int(received[0]) if len(received) == 1 else None)
    replies = []
    for line in text.splitlines():
        ip = re.search(r'(?i)^\s*(?:From|Reply from)\s+(' + IP_RE + r')\s*:', line)
        if (ip and ip[1] == target_ip and re.search(r'(?i)\bbytes\s*[=:]\s*\d+', line)
                and re.search(r'(?i)\bttl\s*[=:]\s*\d+', line)):
            seq = re.search(r'(?i)\bseq\s*[=:]\s*(\d+)', line)
            replies.append({'ip': ip[1], 'seq': int(seq[1]) if seq else None, 'raw': line})
    timeouts = len(re.findall(r'(?im)^\s*(?:Request\s+(?:timeout|timed out)|请求超时)[!.。]?\s*$', text))
    unreachables = len(re.findall(r'(?im)^.*(?:Destination host unreachable|host\s+\S+\s+(?:not\s+reachable|unreachable)|No gateway found).*$', text))
    headers = re.findall(r'(?im)^\s*---\s+(' + IP_RE + r')\s+ping statistics\s+---\s*$', text)
    echo_target = re.search(r'(?im)^\s*Ping\s+' + re.escape(target_ip) + r'(?:\s|:|\[)', text) is not None
    consistent = (sent is not None and recv is not None and headers == [target_ip]
                  and echo_target and sent == requested_count and 0 <= recv <= sent
                  and recv == len(replies) and len({r['seq'] for r in replies if r['seq'] is not None})
                  == len([r for r in replies if r['seq'] is not None]))
    return {'sent': sent, 'received': recv, 'unknown': not consistent,
            'reply_lines': replies, 'timeout_lines': timeouts, 'unreachable_lines': unreachables,
            'target_verified': headers == [target_ip] and echo_target}


class PCConsole:
    def __init__(self, process_id, expected_hosts, *, native=None, timeout=25):
        if isinstance(process_id, bool) or int(process_id) <= 0:
            raise ValueError('需要 eNSP_Client 的有效 PID')
        self.process_id = int(process_id)
        if not 0.05 <= timeout <= 120:
            raise ValueError('命令超时须为 0.05—120 秒')
        self.timeout = timeout
        self.hosts = {}
        for name, original in expected_hosts.items():
            if not re.fullmatch(r'PC[1-4]', name):
                raise ValueError('仅允许本实验 PC1—PC4')
            host = dict(original)
            host['ip'] = str(IPv4Address(host['ip']))
            if not re.fullmatch(r'[0-9a-f]{12}', clean_mac(host.get('mac', ''))):
                raise ValueError(f'{name} 缺少拓扑中的完整 MAC；不能只按标题识别设备')
            host['gateway'] = str(IPv4Address(host.get('gateway') or '0.0.0.0'))
            host['mask'] = str(IPv4Address(host['mask']))
            if host['mask'] != '255.255.255.0':
                raise ValueError('本实验 PC 子网掩码须为 255.255.255.0')
            self.hosts[name] = host
        if not self.hosts or len({h['ip'] for h in self.hosts.values()}) != len(self.hosts):
            raise ValueError('主机表为空或 IP 重复')
        if len({clean_mac(h['mac']) for h in self.hosts.values()}) != len(self.hosts):
            raise ValueError('主机 MAC 重复')
        self.allowed_targets = {h['ip'] for h in self.hosts.values()}
        self.allowed_targets.update(h['gateway'] for h in self.hosts.values() if h['gateway'] != '0.0.0.0')
        self.native = native or Win32Native(self.process_id)
        self.verified, self.required, self.blocked = set(), set(), False

    def _process_guard(self):
        image = self.native.process_image()
        # 使用正反斜线分割，便于跨平台 FakeNative 测试 Windows 路径。
        if re.split(r'[/\\]', image)[-1].lower() != 'ensp_client.exe':
            raise PCConsoleError('进程不是 eNSP_Client，停止；不会调用 Windows ping')
        if self.blocked:
            raise PCConsoleError('上轮命令异常或超时；请手动核对 PC 停止并重新运行助手，不自动重复')

    def _locate(self, source):
        self._process_guard()
        if source not in self.hosts:
            raise ValueError('未知 PC')
        rows = self.native.windows()
        lookup = {row.hwnd: row for row in rows}
        roots = [r for r in rows if r.pid == self.process_id and r.class_name == '#32770'
                 and r.title.strip() in (source, 'PC-' + source, 'PC ' + source) and r.enabled]
        candidates = []
        for row in rows:
            if (row.pid != self.process_id or row.class_name.lower() != 'richedit20a'
                    or row.control_id != COMMAND_CONTROL_ID or not row.enabled):
                continue
            parent, seen = row.hwnd, set()
            while parent in lookup and parent not in seen:
                seen.add(parent)
                for root in roots:
                    if parent == root.hwnd:
                        candidates.append((root.hwnd, row.hwnd))
                parent = lookup[parent].parent
        candidates = list(dict.fromkeys(candidates))
        if len(candidates) != 1:
            raise PCConsoleError(f'{source} 未找到唯一原生命令控件（匹配 {len(candidates)} 个）；请手动打开该 PC 后重试预检')
        return candidates[0]

    def _execute(self, source, command, output_dir=None):
        directory = local_directory(output_dir)
        root, control = self._locate(source)
        before = self.native.text(control)
        if not PROMPT.search(before):
            raise PCConsoleError(f'{source} 未停在空白 PC> 提示符，请手动结束当前命令/清理待输入行')
        result = {'kind': 'eNSP PC 原始命令输出', 'source': source, 'process_id': self.process_id,
                  'window_handle': root, 'control_handle': control, 'command': command,
                  'started_at': stamp(), 'before_text': before, 'after_text': before,
                  'raw_text': '', 'status': 'running', 'manual_stop_required': False,
                  'enter_sent': False,
                  'screenshot': None, 'screenshot_missing': None,
                  'screenshot_scope': '原生PC命令控件1084', 'screenshot_window_handle': control}
        filename = datetime.now().astimezone().strftime('%Y%m%dT%H%M%S.%f%z') + '-' + source + '-' + command.split()[0]
        after = before
        try:
            self.native.submit(control, command, before)
            result['enter_sent'] = True
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                after = self.native.text(control)
                if not after.startswith(before):
                    raise PCConsoleError('命令历史截断或被改写，本轮原文边界丢失，停止且不自动重复')
                delta = after[len(before):]
                if delta and not delta.startswith(command):
                    raise PCConsoleError('本轮命令回显不符，停止且不使用历史结果')
                if len(delta) > len(command) and delta[len(command)] not in '\r\n':
                    raise PCConsoleError('命令回显后的边界不是换行；可能存在用户并发输入，停止本轮')
                if delta.startswith(command) and PROMPT.search(delta):
                    result['status'] = 'completed'
                    break
                time.sleep(0.1)
            else:
                result['status'] = 'timeout'
                self.blocked = True
                result['cancel_attempted'] = True
                try:
                    self.native.interrupt(control)
                    time.sleep(0.1)
                    after = self.native.text(control)
                    result['manual_stop_required'] = not (after.startswith(before) and PROMPT.search(after[len(before):]))
                except (RuntimeError, OSError) as exc:
                    result.update(manual_stop_required=True, cancel_error=str(exc))
        except (RuntimeError, OSError, KeyboardInterrupt) as exc:
            self.blocked = True
            result.update(status='failed', error=str(exc), manual_stop_required=True)
            # 原生输入明确在 Enter 前失败时不再发 Ctrl+C，避免向待输入行插入控制字节。
            no_enter = isinstance(exc, PCConsoleError) and exc.result.get('enter_sent') is False
            if no_enter:
                result['manual_stop_required'] = False
                try:
                    after = self.native.text(control)
                except (RuntimeError, OSError):
                    pass
            else:
                try:
                    self.native.interrupt(control)
                    result['cancel_attempted'] = True
                    after = self.native.text(control)
                    result['manual_stop_required'] = not (after.startswith(before) and PROMPT.search(after[len(before):]))
                except (RuntimeError, OSError):
                    pass
            if isinstance(exc, KeyboardInterrupt):
                result['status'] = 'interrupted'
        finally:
            result.update(after_text=after, completed_at=stamp())
            result['boundary_verified'] = after.startswith(before)
            result['raw_text'] = after[len(before):] if result['boundary_verified'] else ''
            result['raw_file'] = str(directory / (filename + '.txt'))
            with Path(result['raw_file']).open('x', encoding='utf-8', newline='') as stream:
                stream.write('=== BEFORE (原文) ===\n' + before + '\n=== AFTER (原文) ===\n' + after)
            try:
                # 整个 PC 对话框可能仍选中 UDP 标签，必须取实际命令控件，
                # 不通过切页/显窗/合成文字来生成命令截图。
                shot = self.native.screenshot(control, directory / (filename + '.png'))
                result.update(screenshot=shot.get('path'), screenshot_missing=shot.get('missing'))
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                result['screenshot_missing'] = '实窗截图失败，待用户现场截图: ' + str(exc)
            self._save(result, directory / (filename + '.json'))
        return result

    @staticmethod
    def _save(result, path=None):
        target = path or Path(result['raw_file']).with_suffix('.json')
        target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')

    def ipconfig(self, source, output_dir=None):
        result = self._execute(source, 'ipconfig', output_dir)
        result.update(parse_ipconfig(result['raw_text'], self.hosts[source]))
        verified = all(result[key] for key in ('verified_ip', 'verified_mac', 'verified_mask', 'verified_gateway'))
        if not verified:
            if result['status'] == 'completed':
                result.update(status='identity_mismatch', error='PC 实际 IPv4/MAC/掩码/网关与选定工程拓扑不符；停止发包')
            self.verified.discard(source)
        self._save(result)
        return result

    def probe(self, names=None, output_dir=None):
        names = list(self.hosts) if names is None else list(names)
        if not names or len(set(names)) != len(names) or not set(names).issubset(self.hosts):
            raise ValueError('预检 PC 名称为空、重复或未知')
        self.verified.clear()
        self.required = set(names)
        hosts, missing = {}, []
        # 先确认所有必需命令窗口齐全，再只读查询配置。
        for name in names:
            try:
                root, control = self._locate(name)
                hosts[name] = {'window_handle': root, 'control_handle': control}
            except PCConsoleError as exc:
                missing.append(name)
                hosts[name] = {'error': str(exc)}
        if missing:
            return {'status': 'needs_input', 'hosts': hosts, 'missing': missing}
        for name in names:
            result = self.ipconfig(name, output_dir)
            hosts[name].update(result)
            if result['status'] != 'completed' or not all(result[key] for key in ('verified_ip', 'verified_mac', 'verified_mask', 'verified_gateway')):
                return {'status': 'failed', 'hosts': hosts, 'missing': [], 'error': f'{name} IPv4/MAC/掩码/网关或命令状态核验失败'}
            self.verified.add(name)
        return {'status': 'ready', 'hosts': hosts, 'missing': []}

    def _preflight(self, source, output_dir):
        if source not in self.verified or self.verified != self.required:
            raise PCConsoleError('请先 probe 全部本轮必需源 PC，完成 IPv4/MAC 核验后再发包')
        for name in self.required:
            self._locate(name)
        result = self.ipconfig(source, output_dir)
        if result['status'] != 'completed' or not all(result[key] for key in ('verified_ip', 'verified_mac', 'verified_mask', 'verified_gateway')):
            raise PCConsoleError('发包前源 PC IPv4/MAC/掩码/网关再核验失败', result)
        return result

    def ping(self, source, target_ip, count=4, output_dir=None):
        directory = local_directory(output_dir)
        target_ip = str(IPv4Address(target_ip))
        if target_ip not in self.allowed_targets:
            raise ValueError('目标仅允许选定实验的四个 PC IPv4 与网关')
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 4:
            raise ValueError('每次仅允许 1—4 个 ICMP 请求，不自动重复')
        identity = self._preflight(source, directory)
        # 语法由本机 SimPC DLL 的原生帮助字符串实证，host 必须位于参数前。
        command = f'ping {target_ip} -c {count} -w 1000'
        result = self._execute(source, command, directory)
        result.update(parse_ping(result['raw_text'], target_ip, count))
        result.update(target_ip=target_ip, requested_count=count, verified_ip=identity['verified_ip'],
                      verified_mac=identity['verified_mac'], verified_mask=identity['verified_mask'],
                      verified_gateway=identity['verified_gateway'], identity_record=identity['raw_file'])
        if result['status'] != 'completed':
            result['unknown'] = True
        if result['status'] == 'completed' and result['unknown']:
            result['status'] = 'unrecognized_output'
        self._save(result)
        return result

    def clear_arp(self, source, output_dir=None):
        directory = local_directory(output_dir)
        self._preflight(source, directory)
        result = self._execute(source, 'arp -d *', directory)
        result['verified_clear'] = False
        if result['status'] == 'completed':
            readback = self._execute(source, 'arp -a', directory)
            result['readback'] = readback
            raw = readback['raw_text']
            # 即使某条 ARP 行的 MAC/类型无法识别，也先按行首 IP 保留，不能把
            # “未识别该行”误写成已清表。
            addresses = re.findall(r'(?im)^\s*(' + IP_RE + r')(?:\s|$)', raw)
            expected_header = re.search(r'Internet\s+Address\s+Physical\s+Address\s+Type', raw, re.I)
            # arp -d * 成功时可以只返回提示符；以 arp -a 表头与表项回读为依据。
            command_error = re.search(r'(?i)Invalid|Bad argument|Bad IP|Usage:|not been started|unrecognized|unknown command|Error', result['raw_text'] + raw)
            result['verified_clear'] = bool(readback['status'] == 'completed' and expected_header and not command_error
                                            and not (set(addresses) & self.allowed_targets))
            if not result['verified_clear']:
                result['status'] = 'clear_unverified'
        self._save(result)
        return result


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--print-window-worker':
        try:
            _print_window_worker(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        print('请由实验助手调用 PCConsole；本模块不自动打开工程或窗口。')
