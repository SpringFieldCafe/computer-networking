"""用 TShark 离线提取 Ethernet/IPv4/UDP 字段，结果写入本地目录。"""
import argparse
import csv
import io
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ['frame.number', 'frame.time_relative', 'eth.src', 'eth.dst', 'eth.type',
          'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'udp.length']


def analyze(capture, tshark, output, kind):
    if not capture.is_file():
        raise FileNotFoundError('请提供已保存的抓包文件')
    command = [str(tshark), '-n', '-r', 'input.pcap', '-T', 'fields',
               '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d']
    for field in FIELDS:
        command.extend(['-e', field])
    # 旧版 Windows TShark 使用窄字符路径；通过临时英文文件名兼容中文目录。
    with tempfile.TemporaryDirectory(prefix='cn-pcap-') as temporary:
        temp = Path(temporary).resolve()
        assert temp.parent == Path(tempfile.gettempdir()).resolve()
        shutil.copyfile(capture, temp/'input.pcap')
        completed = subprocess.run(command, cwd=temp, capture_output=True, check=False)
    output.mkdir(parents=True, exist_ok=True)
    (output/'tshark-stderr.txt').write_bytes(completed.stderr)
    if completed.returncode:
        raise RuntimeError('TShark 解析失败，请核对抓包格式与本机版本；诊断保存在本地输出目录。')
    text = completed.stdout.decode('utf8', errors='replace')
    rows = list(csv.DictReader(io.StringIO(text)))
    (output/'字段.csv').write_text(text, encoding='utf-8-sig')
    pairs = Counter((r.get('eth.src', ''), r.get('eth.dst', '')) for r in rows if r.get('eth.src'))
    summary = dict(kind=kind, total_frames=len(rows),
                   udp_frames=sum(bool(r.get('udp.srcport')) for r in rows),
                   pairs=[dict(source=a, destination=b, frames=n) for (a, b), n in sorted(pairs.items())])
    (output/'汇总.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf8')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--tshark', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT/'local'/'analysis')
    parser.add_argument('--kind', choices=['实测抓包', '模型示例'], default='实测抓包')
    args = parser.parse_args()
    binary = args.tshark or shutil.which('tshark')
    if binary is None:
        for p in [Path('C:/Program Files/Wireshark/tshark.exe'), Path('C:/Program Files (x86)/Wireshark/tshark.exe')]:
            if p.is_file():
                binary = p
                break
    if binary is None:
        parser.error('请用 --tshark 指定本机 tshark.exe 路径')
    info = analyze(args.capture, binary, args.output, args.kind)
    print(f'已提取 {info["total_frames"]} 帧，其中 UDP {info["udp_frames"]} 帧；结果保存在本地输出目录。')
