"""实验控制台的人工确认、真实进度和会话日志。"""
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import os
import sys
import threading
import time


def disable_quick_edit():
    """只调整本助手控制台，防止选中文字暂停整个控制台进程。"""
    if os.name != 'nt' or not sys.stdin.isatty():
        return False
    import ctypes as C
    from ctypes import wintypes as W
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.GetStdHandle.argtypes = [W.DWORD]
    kernel.GetStdHandle.restype = W.HANDLE
    kernel.GetConsoleMode.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    kernel.SetConsoleMode.argtypes = [W.HANDLE, W.DWORD]
    handle = kernel.GetStdHandle(W.DWORD(-10 & 0xffffffff))
    mode = W.DWORD()
    if not kernel.GetConsoleMode(handle, C.byref(mode)):
        return False
    return bool(kernel.SetConsoleMode(handle, (mode.value | 0x80) & ~0x40))


def _manual_line(title, elapsed, status):
    detail = ('；' + status()) if status else ''
    return f'[等待你操作] {title} | 已等 {int(elapsed)} 秒{detail}'


def confirm(title, status=None, reminder_seconds=15):
    """人工等待不显示虚假的完成百分比；实际按键后立即给出回执。"""
    console_keys = os.name == 'nt' and sys.stdin.isatty()
    if console_keys:
        import msvcrt
        # 在显示新提示之前清空旧按键，不吞掉提示显示后新按下的回车。
        while msvcrt.kbhit():
            msvcrt.getwch()
    print('\n' + _manual_line(title, 0, status), flush=True)
    print('准备好后：先点击本助手窗口，再按一次回车继续；按 Q 退出。', flush=True)
    print('若窗口处于“选择/标记”状态，先按 Esc 取消选择。此处不会自动发包。', flush=True)
    if console_keys:
        started = last = time.monotonic()
        while True:
            if msvcrt.kbhit():
                key = msvcrt.getwch()
                if key in ('\r', '\n'):
                    break
                if key in ('q', 'Q', '\x03'):
                    raise KeyboardInterrupt()
                if key in ('\x00', '\xe0') and msvcrt.kbhit():
                    msvcrt.getwch()
            now = time.monotonic()
            if now - last >= reminder_seconds:
                print(_manual_line(title, now - started, status), flush=True)
                last = now
            time.sleep(.1)
    else:
        try:
            if input('请按回车继续：').strip().lower() == 'q':
                raise KeyboardInterrupt()
        except EOFError as exc:
            raise RuntimeError('没有可读取的键盘输入，请从“开始实验.cmd”交互运行。') from exc
    print('[已收到确认] 正在进入下一阶段……', flush=True)


class Activity:
    """数量来自实际检查/命令；未知总量时仅显示运行状态和耗时。"""
    def __init__(self, title, total=None, interval=2):
        self.title, self.total, self.interval = title, total, interval
        self.done, self.detail = 0, '开始处理'
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.started = None

    def update(self, detail=None, done=None, total=None):
        with self.lock:
            if detail is not None:
                self.detail = detail
            if done is not None:
                self.done = done
            if total is not None:
                self.total = total

    def line(self, label='执行中'):
        with self.lock:
            detail, done, total = self.detail, self.done, self.total
        elapsed = time.monotonic() - self.started
        if total:
            filled = min(20, int(20 * done / total))
            bar = '[' + '#' * filled + '-' * (20 - filled) + f'] {done}/{total}'
        else:
            bar = '|/-\\'[int(elapsed) % 4]
        return f'[{label}] {self.title} {bar} | {elapsed:.0f} 秒 | {detail}'

    def _tick(self):
        while not self.stop.wait(self.interval):
            print(self.line(), flush=True)

    def __enter__(self):
        self.started = time.monotonic()
        print(self.line(), flush=True)
        self.thread = threading.Thread(target=self._tick, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, typ, value, tb):
        self.stop.set()
        self.thread.join(timeout=1)
        print(self.line('已完成' if typ is None else '已停止'), flush=True)


class Tee:
    def __init__(self, console, log, lock):
        self.console, self.log, self.lock = console, log, lock

    def write(self, text):
        with self.lock:
            self.console.write(text)
            self.log.write(text)
            self.log.flush()
        return len(text)

    def flush(self):
        with self.lock:
            self.console.flush()
            self.log.flush()

    def isatty(self):
        return self.console.isatty()

    def __getattr__(self, name):
        return getattr(self.console, name)


@contextmanager
def session_log(root):
    folder = Path(root) / 'logs'
    folder.mkdir(exist_ok=True)
    path = folder / (datetime.now().strftime('helper-%Y%m%d-%H%M%S-%f') + f'-{os.getpid()}.txt')
    stdout, stderr = sys.stdout, sys.stderr
    with path.open('x', encoding='utf-8', buffering=1) as log:
        lock = threading.RLock()
        sys.stdout, sys.stderr = Tee(stdout, log, lock), Tee(stderr, log, lock)
        try:
            print('助手全过程日志：' + str(path), flush=True)
            yield path
        finally:
            sys.stdout, sys.stderr = stdout, stderr
