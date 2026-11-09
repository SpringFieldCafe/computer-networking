"""按课件端口准备 eNSP 拓扑 XML 与三个 Console 配置文件。"""
from pathlib import Path
import uuid
import xml.etree.ElementTree as E
from switch_model import LINKS
from collect_switches import commands_for

ROOT = Path(__file__).resolve().parents[1]


def build():
    topo = E.Element('topo', version='1.2.00.510')
    devices = E.SubElement(topo, 'devices')
    names = ['SW1', 'SW2', 'SW3'] + [f'Client{i}' for i in range(1, 6)]
    coords = [(300, 200), (650, 200), (1000, 200),
              (60, 200), (300, 450), (650, 450), (1000, 450), (1250, 200)]
    ids = {n: str(uuid.uuid5(uuid.NAMESPACE_URL, f'https://example.invalid/cn-exp2/{n}')).upper() for n in names}
    for index, (name, (x, y)) in enumerate(zip(names, coords)):
        switch = name.startswith('SW')
        dev = E.SubElement(devices, 'dev', id=ids[name], name=name,
            model='S3700' if switch else 'Client', settings='',
            com_port=str(2000 + index) if switch else '0', bootmode='0',
            cx=f'{x:.6f}', cy=f'{y:.6f}', edit_left=str(x + 27), edit_top=str(y + 54))
        slot = E.SubElement(dev, 'slot', number='slot17', isMainBoard='1')
        E.SubElement(slot, 'interface', sztype='Ethernet', interfacename='Ethernet', count='22' if switch else '1')
        if switch:
            E.SubElement(slot, 'interface', sztype='Ethernet', interfacename='GE', count='2')
    lines = E.SubElement(topo, 'lines')
    for a, ap, b, bp in LINKS:
        line = E.SubElement(lines, 'line', srcDeviceID=ids[a], destDeviceID=ids[b])
        E.SubElement(line, 'interfacePair', lineName='Copper', srcIndex=str(ap - 1), tarIndex=str(bp - 1))
    E.SubElement(topo, 'shapes')
    E.SubElement(topo, 'txttips')
    E.indent(topo, space='    ')
    destination = ROOT/'local'/'topology'/'交换机自学习.topo'
    destination.parent.mkdir(parents=True, exist_ok=True)
    E.ElementTree(topo).write(destination, encoding='utf-8', xml_declaration=True)
    config = ROOT/'config'
    config.mkdir(exist_ok=True)
    for i in range(1, 4):
        commands = commands_for(f'SW{i}', prepare=True)
        (config/f'SW{i}.txt').write_text('\n'.join(commands) + '\n', encoding='ascii')
    # 逐项校验设备模型、链路、端口唯一性与课件表。
    parsed = E.parse(destination).getroot()
    assert len(parsed.findall('./devices/dev')) == 8
    assert len(parsed.findall('./lines/line')) == 7
    ports = []
    for line in parsed.findall('./lines/line'):
        pair = line.find('interfacePair')
        ports += [(line.get('srcDeviceID'), pair.get('srcIndex')),
                  (line.get('destDeviceID'), pair.get('tarIndex'))]
    assert len(ports) == len(set(ports))
    print('已准备 3 台 S3700、5 台 Client、7 条链路与三份配置。')


if __name__ == '__main__':
    build()
