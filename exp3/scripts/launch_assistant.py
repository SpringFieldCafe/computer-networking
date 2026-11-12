"""用户主动启动的入口：仅在 eNSP 已提升权限时匹配权限，再打开菜单。"""
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def needs_elevation(controller_elevated, target_states):
    return controller_elevated is False and any(value is True for value in target_states)


def process_elevated(pid=None):
    if sys.platform != 'win32':
        return None
    kernel = C.WinDLL('kernel32', use_last_error=True)
    advapi = C.WinDLL('advapi32', use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [W.DWORD, W.BOOL, W.DWORD], W.HANDLE
    kernel.GetCurrentProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = [W.HANDLE]
    advapi.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    advapi.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, W.LPVOID, W.DWORD, C.POINTER(W.DWORD)]
    process = kernel.GetCurrentProcess() if pid is None else kernel.OpenProcess(0x1000, False, pid)
    token, value, length = W.HANDLE(), W.DWORD(), W.DWORD()
    try:
        if not process or not advapi.OpenProcessToken(process, 8, C.byref(token)):
            return None
        if not advapi.GetTokenInformation(token, 20, C.byref(value), C.sizeof(value), C.byref(length)):
            return None
        return bool(value.value)
    finally:
        if token:
            kernel.CloseHandle(token)
        if pid is not None and process:
            kernel.CloseHandle(process)


def ensp_pids():
    command = '@(Get-Process -Name eNSP_Client -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id) | ConvertTo-Json -Compress'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, timeout=15, check=False,
                            creationflags=0x08000000 if sys.platform == 'win32' else 0)
    if result.returncode:
        return []
    values = json.loads(result.stdout.decode('utf-8-sig').strip() or '[]')
    return [values] if isinstance(values, int) else values


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv) or ['menu']
    assistant = ROOT/'scripts'/'assistant.py'
    states = [process_elevated(pid) for pid in ensp_pids()] if sys.platform == 'win32' else []
    current = process_elevated()
    launch = {'checked_at': datetime.now(timezone(timedelta(hours=8))).isoformat(),
              'controller_elevated': current, 'ensp_elevated_states': states,
              'elevation_required': needs_elevation(current, states)}
    folder = ROOT/'local'/'launch'
    folder.mkdir(parents=True, exist_ok=True)
    (folder/('launch-'+datetime.now().strftime('%Y%m%dT%H%M%S.%f')+'.json')).write_text(
        json.dumps(launch, ensure_ascii=False, indent=2), encoding='utf-8')
    if launch['elevation_required']:
        print('eNSP正在以管理员身份运行。为允许PC后台输入，Windows将请求以相同权限启动助手。', flush=True)
        shell = C.WinDLL('shell32', use_last_error=True)
        shell.ShellExecuteW.argtypes = [W.HWND, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, C.c_int]
        shell.ShellExecuteW.restype = C.c_ssize_t
        result = shell.ShellExecuteW(None, 'runas', sys.executable,
                                    subprocess.list2cmdline(['-X', 'utf8', str(assistant), *args]), str(ROOT.parent), 1)
        if result <= 32:
            print('同权限启动未完成；请重新运行入口并查看Windows提示。')
            return 1
        return 0
    return subprocess.call([sys.executable, '-X', 'utf8', str(assistant), *args], cwd=ROOT.parent)


if __name__ == '__main__':
    sys.exit(main())
