#!/usr/bin/env python3
"""THROWAWAY issue #24. Native read-only observation; refusal cases are synthetic.

No real store is opened. Object tuples below belong only to newly made fixtures.
This is a candidate format/refusal model, not an approved identity migration.
"""
import ctypes
import json
from pathlib import Path
import re
import shutil
import time
import uuid

PROVIDER = 'darwin-kern.bootsessionuuid/v1'
SCHEMA = 'work-host-local-identity/v1'


def parse_boot(provider, raw):
    if provider != PROVIDER:
        raise ValueError('incompatible provider')
    if len(raw) != 37 or raw[-1:] != b'\0':
        raise ValueError('invalid native string framing')
    text = raw[:-1].decode('ascii')
    if not re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', text):
        raise ValueError('invalid UUID shape')
    value = uuid.UUID(text)
    if value.int == 0:
        raise ValueError('nil UUID')
    # UUID case is representation, not a boot transition. No .strip() fallback.
    return str(value)


def stable_boot(provider):
    first = parse_boot(PROVIDER, provider())
    last = parse_boot(PROVIDER, provider())
    if first != last:
        raise ValueError('boot changed during collection')
    return first


def native_read():
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    call = libc.sysctlbyname
    call.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    call.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(128)
    size = ctypes.c_size_t(len(buffer))
    # newp=NULL/newlen=0: read only. The actual UUID is never printed/published.
    if call(b'kern.bootsessionuuid', buffer, ctypes.byref(size), None, 0) != 0:
        raise OSError(ctypes.get_errno(), 'sysctl read failed')
    if size.value > len(buffer):
        raise ValueError('oversized sysctl result')
    return buffer.raw[:size.value]


def record(root, boot):
    stat = root.stat()
    return {'schema': SCHEMA, 'boot': {'provider': PROVIDER, 'uuid': boot},
            'store_object': {'device': stat.st_dev, 'file_id': stat.st_ino}}


def admit_same_boot(prior, root, boot):
    if prior['schema'] != SCHEMA or prior['boot']['provider'] != PROVIDER:
        raise ValueError('incompatible historical identity')
    if prior['boot']['uuid'] != boot:
        raise ValueError('new boot requires reconciliation, not admission')
    if prior['store_object'] != record(root, boot)['store_object']:
        raise ValueError('store root replaced or copied')


def run():
    observations = []
    for _ in range(5):
        observations.append(native_read())
        time.sleep(0.1)
    values = [parse_boot(PROVIDER, raw) for raw in observations]
    assert len(set(values)) == 1
    print(json.dumps({'kind': 'native-boot-read-only', 'reads': 5,
                      'returned_bytes': [len(raw) for raw in observations],
                      'nul_terminated': all(raw[-1:] == b'\0' for raw in observations),
                      'uppercase_text': all(raw[:-1] == raw[:-1].upper() for raw in observations),
                      'canonical_values_equal': len(set(values)) == 1,
                      'raw_identity_omitted': True}))
    a = b'12345678-1234-4234-9234-123456789ABC\0'
    b = b'87654321-1234-4234-9234-123456789ABC\0'
    count = 0

    def refuses(name, function):
        nonlocal count
        try:
            function()
        except (ValueError, UnicodeError):
            print(json.dumps({'kind': 'synthetic-refusal', 'case': name, 'refused': True}))
            count += 1
        else:
            raise AssertionError('failed refusal: ' + name)

    for name, raw in [('absent', b''), ('missing-nul', a[:-1]),
                      ('trailing-newline', a[:-1] + b'\n\0'),
                      ('embedded-nul', a[:9] + b'\0' + a[10:]),
                      ('bad-hex', b'Z' + a[1:]),
                      ('nil', b'00000000-0000-0000-0000-000000000000\0')]:
        refuses(name, lambda raw=raw: parse_boot(PROVIDER, raw))
    refuses('legacy-linux-provider', lambda: parse_boot('linux-procfs/v1', a))
    sequence = iter([a, b])
    refuses('boot-changed-during-collection', lambda: stable_boot(lambda: next(sequence)))
    assert stable_boot(lambda: a) == parse_boot(PROVIDER, a.lower())
    sample = record(Path('fixtures/identity-original'), values[0])
    admit_same_boot(sample, Path('fixtures/identity-original'), values[0])
    # This JSON round trip uses synthetic UUID text, not the real host UUID.
    serial = record(Path('fixtures/identity-original'), parse_boot(PROVIDER, a))
    assert json.loads(json.dumps(serial, sort_keys=True)) == serial
    refuses('copied-store', lambda: admit_same_boot(sample, Path('fixtures/identity-copy'), values[0]))
    refuses('changed-boot-needs-reconciliation', lambda: admit_same_boot(sample, Path('fixtures/identity-original'), parse_boot(PROVIDER, b)))
    legacy = dict(sample, schema='linux-checkout-identity/unversioned')
    refuses('historical-unversioned-schema', lambda: admit_same_boot(legacy, Path('fixtures/identity-original'), values[0]))
    print(json.dumps({'kind': 'identity-summary', 'synthetic_refusals': count,
                      'json_round_trip': True, 'case_normalization': True,
                      'same_fixture_admitted': True, 'actual_store_opened': False}))


if __name__ == '__main__':
    original = Path('fixtures/identity-original')
    original.mkdir()
    (original / 'prototype-marker').write_text('synthetic, not Work authority\n')
    shutil.copytree(original, Path('fixtures/identity-copy'))
    run()
