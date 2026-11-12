"""验证公开副本的协议校验和、日志/抓包对应关系与拒绝未知字段的行为。"""
import csv
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import xml.etree.ElementTree as E

from export_public import read_pcap, udp_packet, stp_packet, scrub_console, export

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'evidence'
MANIFEST = json.loads((DATA / 'manifest.json').read_text('utf-8'))


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total


class PublicEvidenceTests(unittest.TestCase):
    def test_all_frames_counts_and_protocol_checksums(self):
        udp, stp, stamps = 0, 0, []
        for path in sorted((DATA / 'pcap').glob('*.pcap')):
            previous = -1
            for _, stamp, frame, wire in read_pcap(path):
                self.assertGreaterEqual(stamp, previous)
                previous = stamp
                stamps.append(stamp)
                self.assertEqual(wire, len(frame))
                if frame[12:14] == b'\x08\x00':
                    udp += 1
                    udp_packet(frame, MANIFEST)
                    ip = frame[14:]
                    self.assertEqual(checksum(ip[:20]), 0xffff)
                    pseudo = ip[12:20] + b'\0\x11' + struct.pack('!H', len(ip)-20)
                    self.assertEqual(checksum(pseudo + ip[20:]), 0xffff)
                else:
                    stp += 1
                    self.assertEqual(stp_packet(frame, MANIFEST), frame)
        self.assertEqual((udp, stp, min(stamps)), (26, 27, 0))

    def test_inventory_hashes(self):
        inventory = json.loads((DATA / 'inventory.json').read_text('utf-8'))
        self.assertEqual(inventory['total_frames'], 53)
        for name, digest in inventory['sha256'].items():
            self.assertEqual(hashlib.sha256((DATA/name).read_bytes()).hexdigest(), digest, name)

    def test_csv_source_numbers_and_lengths_match_captures(self):
        with (DATA/'frames.csv').open(encoding='utf-8', newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 53)
        for row in rows:
            _, stamp, packet, wire = list(read_pcap(DATA/'pcap'/(row['link']+'.pcap')))[int(row['public_frame'])-1]
            self.assertEqual(row['public_frame'], row['source_frame'])
            self.assertEqual(int(row['wire_length']), wire)
            self.assertEqual(row['eth.src'], packet[6:12].hex(':'))
            self.assertAlmostEqual(float(row['relative_seconds']), stamp / 1e9, places=6)

    def test_project_and_data_share_identifiers(self):
        folder = ROOT/'pc-assistant'
        manifest = json.loads((folder/'manifest.json').read_text('utf-8'))
        self.assertEqual(manifest, MANIFEST)
        topo = E.parse(folder/manifest['project']).getroot()
        by_name = {d.get('name'): d for d in topo.findall('./devices/dev')}
        self.assertEqual(len(by_name), 8)
        self.assertEqual(len(topo.findall('./lines/line')), 7)
        for group in ('pcs', 'switches'):
            for name, item in manifest[group].items():
                self.assertEqual(by_name[name].get('system_mac'), item['mac'])
                self.assertEqual(by_name[name].get('id'), item['id'])

    def test_unknown_console_address_and_path_are_rejected(self):
        for text in ('aaaa-bbbb-cccc 1 - - Eth0/0/1 dynamic', 'C:\\Users\\example\\capture.pcap', 'Password: example'):
            with self.assertRaises(ValueError):
                scrub_console(text, MANIFEST)

    def test_unknown_ip_and_mst_name_are_rejected(self):
        packets = [row[2] for row in read_pcap(DATA/'pcap/Client1-SW1.pcap')]
        udp = bytearray(next(p for p in packets if p[12:14] == b'\x08\x00'))
        udp[26:30] = bytes([10, 0, 0, 1])
        with self.assertRaises(ValueError):
            udp_packet(bytes(udp), MANIFEST)
        bpdu = bytearray(next(p for p in packets if p[12:14] != b'\x08\x00'))
        bpdu[56:60] = b'name'
        with self.assertRaises(ValueError):
            stp_packet(bytes(bpdu), MANIFEST)

    def test_source_nesting_is_rejected_before_reading_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)/'source'
            source.mkdir()
            with self.assertRaises(ValueError):
                export(source, source/'output')
            self.assertEqual(list(source.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
