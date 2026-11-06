#!/usr/bin/env python3
"""THROWAWAY bounded matrix. Run once in a fresh scratch directory on macOS.

All write destinations are relative to cwd, including compiler temporary files.
No reboot, mount, installation, existing database or repository operation occurs.
"""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path.cwd()
SDK = '/Library/Developer/CommandLineTools/SDKs/MacOSX27.0.sdk'
ENV = dict(os.environ, TMPDIR=str(ROOT / '.tmp'))


def command(args, expected=0, timeout=30):
    child = subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=timeout)
    if child.returncode != expected:
        raise RuntimeError('probe command failed: ' + args[0] + '\n' + child.stderr)
    return child.stdout


def rows(text):
    return [json.loads(line) for line in text.splitlines() if line]


def fixture(name):
    path = Path('fixtures') / name
    path.mkdir()  # Refuse reuse. Never open an existing database or marker.
    return str(path)


def main():
    if Path('results/matrix.json').exists():
        raise RuntimeError('results exist: use a fresh scratch directory')
    for path in ('.tmp', 'fixtures', 'results'):
        Path(path).mkdir(exist_ok=True)
    if not Path(SDK).is_dir():
        raise RuntimeError('documented SDK absent; no automatic discovery or install')
    if not Path('sources/sqlite_full_fsync.inc').exists():
        command(['/usr/bin/python3', 'fetch_sources.py'], timeout=240)
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O0', '-isysroot', SDK]
    command(['/usr/bin/clang'] + flags + ['native_probe.c', '-lsqlite3', '-o', 'native_probe'], timeout=60)
    command(['/usr/bin/clang'] + flags + ['sqlite_fallback_probe.c', '-o', 'sqlite_fallback_probe'], timeout=60)
    result = {'scope': 'throwaway scratch matrix; not native reboot or power-loss qualification'}
    result['environment'] = {
        'macos_version': command(['/usr/bin/sw_vers', '-productVersion']).strip(),
        'macos_build': command(['/usr/bin/sw_vers', '-buildVersion']).strip(),
        'kernel': command(['/usr/bin/uname', '-srvm']).strip(),
        'compiler': command(['/usr/bin/clang', '--version']).splitlines()[:2],
        'sdk': '27.0 (explicit existing SDK directory)',
        'python': command(['/usr/bin/python3', '--version']).strip(),
    }
    result['native'] = rows(command(['./native_probe', 'native', fixture('matrix-native')]))
    result['sqlite_system'] = []
    for setting, name in enumerate(('default', 'checkpoint-only', 'all-fullsync')):
        observed = rows(command(['./native_probe', 'sqlite', fixture('sqlite-' + name), str(setting)]))
        result['sqlite_system'].append({'configuration': name, 'observations': observed,
                                        'syscall_trace': False, 'bundled_library_tested': False})
    result['process_exit'] = []
    for phase, name in enumerate(('before-commit', 'after-commit', 'after-marker')):
        path = fixture('process-exit-' + name)
        child = rows(command(['./native_probe', 'crash', path, str(phase)], expected=77))
        observed = rows(command(['./native_probe', 'reopen', path]))
        assert observed[0]['rows'] == (0 if phase == 0 else 1)
        assert observed[0]['marker'] == (phase == 2)
        assert observed[0]['integrity_ok'] == 1
        result['process_exit'].append({'phase': name, 'child_exit': 77,
                                       'sync_observations': child, 'reopen': observed})
    result['sqlite_extracted_synthetic'] = rows(command(['./sqlite_fallback_probe']))
    result['identity'] = rows(command(['/usr/bin/python3', 'identity_probe.py']))
    Path('results/matrix.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: native sync, 3 system-SQLite settings, 3 process-exit boundaries, 4 extracted-function cases, boot and synthetic identity cases')


if __name__ == '__main__':
    main()
