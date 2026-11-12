"""按正在运行的dumpcap识别抓包，并从真实PCAP提取本轮记录。"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import os
import re
import struct
import time


def _image_process_ids(image_name):
    if os.name != 'nt':
        raise RuntimeError('本助手的抓包进程识别需要Windows。')
    class ProcessEntry(C.Structure):
        _fields_=[('dwSize',W.DWORD),('cntUsage',W.DWORD),('th32ProcessID',W.DWORD),
                  ('th32DefaultHeapID',C.c_size_t),('th32ModuleID',W.DWORD),
                  ('cntThreads',W.DWORD),('th32ParentProcessID',W.DWORD),
                  ('pcPriClassBase',W.LONG),('dwFlags',W.DWORD),('szExeFile',W.WCHAR*260)]
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes=[W.DWORD,W.DWORD]
    kernel.CreateToolhelp32Snapshot.restype=W.HANDLE
    kernel.Process32FirstW.argtypes=[W.HANDLE,C.POINTER(ProcessEntry)]
    kernel.Process32NextW.argtypes=[W.HANDLE,C.POINTER(ProcessEntry)]
    kernel.CloseHandle.argtypes=[W.HANDLE]
    handle=kernel.CreateToolhelp32Snapshot(2,0)
    if handle in (None,C.c_void_p(-1).value):
        raise RuntimeError('读取抓包进程列表失败，请保留当前窗口的报错。')
    result=set()
    try:
        entry=ProcessEntry();entry.dwSize=C.sizeof(entry)
        ok=kernel.Process32FirstW(handle,C.byref(entry))
        while ok:
            if entry.szExeFile.lower()==image_name.lower():result.add(entry.th32ProcessID)
            ok=kernel.Process32NextW(handle,C.byref(entry))
    finally:kernel.CloseHandle(handle)
    return result


def dumpcap_pids():
    return _image_process_ids('dumpcap.exe')


def active_paths(paths,pids=None):
    """本机Wireshark 1.4临时文件名末尾包含负责写入它的dumpcap PID。"""
    pids=dumpcap_pids() if pids is None else set(pids)
    selected=set()
    for p in paths:
        match=re.fullmatch(r'wireshark.*a(\d+)',p.name,re.I)
        if match and int(match.group(1)) in pids:selected.add(p)
    return selected


def pcap_layout(path):
    data=Path(path).read_bytes()
    formats={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',
             b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}
    if len(data)<24 or data[:4] not in formats:
        raise ValueError('需要完整的PCAP文件头。')
    endian=formats[data[:4]]
    if struct.unpack_from(endian+'I',data,20)[0]!=1:
        raise ValueError('抓包链路类型应为Ethernet。')
    offset=24;ends=[24]
    while offset<len(data):
        if offset+16>len(data):raise ValueError('抓包记录正在写入，请稍后重试。')
        length=struct.unpack_from(endian+'I',data,offset+8)[0]
        offset+=16+length
        if offset>len(data):raise ValueError('抓包帧正在写入，请稍后重试。')
        ends.append(offset)
    return data,ends


def checkpoint(paths,manifest,progress=None):
    from evidence import inspect
    result=[];links=[]
    for n,p in enumerate(sorted(paths),1):
        if progress:progress('记录抓包起点：'+p.name,n-1,len(paths))
        deadline=time.monotonic()+3
        while True:
            try:
                data,ends=pcap_layout(p)
                info=inspect(p,manifest)
                break
            except ValueError as exc:
                if not any(s in str(exc) for s in ['正在写入','尚未写完','文件头']) or time.monotonic()>=deadline:
                    raise
                if progress:progress('抓包正在写入，等待完整记录（最多3秒）：'+p.name,n-1,len(paths))
                time.sleep(.1)
        if info['link']:links.append(info['link'])
        st=p.stat()
        result.append({'file':str(p.resolve()),'start_frame':len(ends)-1,
                       'start_offset':ends[-1],'header_hex':data[:24].hex(),
                       'file_identity':[st.st_dev,st.st_ino],'link_hint':info['link']})
        if progress:progress(f'第{n}份起点已记录，跳过之前的{len(ends)-1}帧',n,len(paths))
    if len(links)!=len(set(links)):
        raise RuntimeError('已有抓包中检测到重复链路，请每条链路只保留一份；尚未清表或发包。')
    return result


def export_window(raw_path,target,selection):
    """只复制原始记录字节；不改时间戳、帧内容或长度，不合成实验帧。"""
    data,ends=pcap_layout(raw_path)
    start=selection['start_offset']
    if data[:24].hex()!=selection['header_hex'] or start not in ends:
        raise ValueError('抓包文件在实验中被替换或截断，请保留原始文件核查。')
    Path(target).write_bytes(data[:24]+data[start:])
    return len(ends)-1-selection['start_frame']
