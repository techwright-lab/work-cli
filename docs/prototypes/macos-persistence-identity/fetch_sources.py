#!/usr/bin/env python3
"""Fetch bounded public primary-source evidence into this scratch directory only."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

OUT = Path('sources')
OUT.mkdir(exist_ok=True)

def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    assert len(data) <= 16 * 1024 * 1024
    return data

records = []
urls = {
    'rust-unix.rs': 'https://raw.githubusercontent.com/rust-lang/rust/1.98.1/library/std/src/sys/fs/unix.rs',
    'fsync.2': 'https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fsync.2',
    'fcntl.2': 'https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fcntl.2',
    'kern_sysctl.c': 'https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sysctl.c',
    'pragma.html': 'https://sqlite.org/pragma.html',
}
for name, url in urls.items():
    data = fetch(url)
    (OUT / name).write_bytes(data)
    records.append({'name': name, 'url': url, 'sha256': hashlib.sha256(data).hexdigest()})
url = 'https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.36.0.crate'
data = fetch(url)
sha = hashlib.sha256(data).hexdigest()
assert sha == '95b4103cffefa72eb8428cb6b47d6627161e51c2739fc5e3b734584157bc642a'
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    for name in ('sqlite3/sqlite3.c', 'sqlite3/sqlite3.h', 'build.rs'):
        member = archive.extractfile('libsqlite3-sys-0.36.0/' + name)
        assert member is not None
        (OUT / Path(name).name).write_bytes(member.read())
text = (OUT / 'sqlite3.c').read_text()
start = text.index('static int full_fsync(int fd, int fullSync, int dataOnly){')
end = text.index('\n}\n', start) + 3
(OUT / 'sqlite_full_fsync.inc').write_text(text[start:end])
records.append({'name': 'libsqlite3-sys-0.36.0.crate', 'url': url, 'sha256': sha})
Path('source_manifest.json').write_text(json.dumps(records, indent=2) + '\n')
print('Verified locked crate SHA-256; fetched Rust, Apple and SQLite primary sources.')
