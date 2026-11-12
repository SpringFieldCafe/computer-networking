"""从公开工程生成独立本地运行副本；生成新设备 ID，不带 flash 和报告原件。"""
import argparse
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import re
import shutil
import uuid
import xml.etree.ElementTree as E

ROOT = Path(__file__).resolve().parent


def load(path):
    raw = Path(path).read_bytes()
    text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
    return E.fromstring(re.sub(r'^\s*<\?xml[^>]*\?>', '', text))


def build(destination):
    destination = Path(destination).resolve()
    if destination == ROOT or ROOT in destination.parents:
        raise ValueError('运行副本应存放到源码目录以外，例如 exp2/local/pc-assistant/批次')
    manifest = json.loads((ROOT / 'manifest.json').read_text('utf-8'))
    topo = deepcopy(load(ROOT / manifest['project']))
    mapping = {}
    for device in topo.findall('./devices/dev'):
        old, name = device.get('id'), device.get('name')
        fresh = str(uuid.uuid4()).upper()
        mapping[old] = fresh
        device.set('id', fresh)
        manifest['switches' if name.startswith('SW') else 'pcs'][name]['id'] = fresh
    for line in topo.findall('./lines/line'):
        for key in ('srcDeviceID', 'destDeviceID'):
            line.set(key, mapping[line.get(key)])
    destination.mkdir(parents=True, exist_ok=False)
    for pattern in ('*.py', '*.ps1', '*.cmd', 'README.md'):
        for path in ROOT.glob(pattern):
            # 生成器保留在公开源码目录，运行副本只带实验入口。
            if path.name != 'build_copy.py':
                shutil.copyfile(path, destination / path.name)
    # check_project 只需只读 XML 载入函数。
    (destination / 'build_copy.py').write_text(
        'from pathlib import Path\nimport re\nimport xml.etree.ElementTree as E\n'
        'def load(path):\n'
        '    raw=Path(path).read_bytes()\n'
        '    text=raw.decode("utf-16" if raw[:2] in (b"\\xff\\xfe",b"\\xfe\\xff") else "utf-8-sig")\n'
        '    return E.fromstring(re.sub(r"^\\s*<\\?xml[^>]*\\?>", "", text))\n', 'utf-8')
    shutil.copytree(ROOT / 'scripts', destination / 'scripts', ignore=shutil.ignore_patterns('__pycache__'))
    E.indent(topo, space='    ')
    E.ElementTree(topo).write(destination / manifest['project'], encoding='utf-8', xml_declaration=True)
    (destination / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', 'utf-8')
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT.parent / 'local' / 'pc-assistant' / datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    args = parser.parse_args()
    print('已生成独立运行副本：' + str(build(args.output)))
    print('在 eNSP 打开副本中的 topo，启动全部设备，再运行副本中的开始实验.cmd。')


if __name__ == '__main__':
    main()
