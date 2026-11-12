"""复核准备材料：测试、工程结构、原件哈希与本地隐私排除，自动留日志。"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from lab_spec import EXPERIMENTS, TOPOLOGY_FILES
from prepare_topology import read_topology, validate_topology
from collect_switches import latest_bundle

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def main():
    now = datetime.now(timezone(timedelta(hours=8)))
    output = ROOT/'local'/'verification'/now.strftime('%Y%m%dT%H%M%S.%f%z')
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': '准备验证，非eNSP通信实测', 'started_at': now.isoformat(), 'checks': {}, 'errors': []}
    suite = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'unittest', 'discover',
                            '-s', str(ROOT/'scripts'), '-p', 'test_*.py', '-v'],
                           cwd=REPO, capture_output=True, timeout=180, check=False)
    (output/'tests-stdout.txt').write_bytes(suite.stdout)
    (output/'tests-stderr.txt').write_bytes(suite.stderr)
    result['checks']['unit_tests'] = {'returncode': suite.returncode, 'command': suite.args}
    if suite.returncode:
        result['errors'].append('测试失败，请检查 tests-stderr.txt')
    try:
        bundle = latest_bundle()
        manifest = json.loads((bundle/'manifest.json').read_text(encoding='utf-8'))
        result['checks']['topology'] = {}
        for part in EXPERIMENTS:
            path = bundle/TOPOLOGY_FILES[part]
            if hashlib.sha256(path.read_bytes()).hexdigest() != manifest['files_sha256'][path.name]:
                raise ValueError('准备拓扑哈希与批次清单不同')
            result['checks']['topology'][part] = validate_topology(read_topology(path), part, manifest)
        result['bundle'] = str(bundle)
    except (OSError, ValueError, KeyError) as exc:
        result['errors'].append(str(exc))
    source_manifest = ROOT/'local'/'sources'/'originals-sha256.json'
    result['checks']['source_integrity'] = '未提供原件基线'
    if source_manifest.exists():
        original = json.loads(source_manifest.read_text(encoding='utf-8'))
        preserved = all(hashlib.sha256((ROOT/item['name']).read_bytes()).hexdigest() == item['sha256']
                        for item in original['files'])
        result['checks']['source_integrity'] = preserved
        if not preserved:
            result['errors'].append('课程原件哈希发生变化，请保留现状并核查')
    private_paths = ['AGENTS.md', 'exp3/local/records/example.txt', 'exp3/local/topology/example.topo',
                     'exp3/local/evidence/example.json', 'exp3/local/analysis/example.csv',
                     'exp3/local/runs/example/run.json', 'exp3/local/state/part1-capture-map.json',
                     'exp3/local/launch/example.json',
                     'exp3/计算机网络实验三.pptx', 'exp3/实验三报告模板.doc', '作业三/privacy-probe.txt']
    ignored = subprocess.run(['git', 'check-ignore', '--stdin'], input=('\n'.join(private_paths)+'\n').encode('utf-8'),
                             cwd=REPO, capture_output=True, check=False, timeout=15)
    (output/'git-ignore-stdout.txt').write_bytes(ignored.stdout)
    (output/'git-ignore-stderr.txt').write_bytes(ignored.stderr)
    # 每个路径单独核对，避免 Git 的非 ASCII 路径转义影响清单比对。
    missing = [path for path in private_paths if subprocess.run(
        ['git', 'check-ignore', '--quiet', '--', path], cwd=REPO, capture_output=True,
        check=False, timeout=10).returncode != 0]
    result['checks']['privacy_exclusions'] = {'tested': len(private_paths), 'missing': missing}
    if missing:
        result['errors'].append('存在未被忽略的本地材料路径')
    result.update(finished_at=datetime.now(timezone(timedelta(hours=8))).isoformat(),
                  status='passed' if not result['errors'] else 'failed')
    (output/'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'准备验证：{result["status"]}；详细日志：{output}')
    return int(bool(result['errors']))


if __name__ == '__main__':
    sys.exit(main())
