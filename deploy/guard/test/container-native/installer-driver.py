#!/usr/bin/python3
"""TEST ONLY local immutable image admission; production operation code is otherwise exact."""
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path('/var/lib/zunder-container-installer-native')
spec = importlib.util.spec_from_file_location('operations', ROOT / 'operations.py')
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)
original_validate = ops.validate
config = json.loads((ROOT / 'fixture.json').read_text())
def fixture_validate(record):
    ops.require(record['image'] == config['image'], 'Unexpected local fixture image.')
    original_validate({**record, 'image': 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'a' * 64})
ops.validate = fixture_validate
if __name__ == '__main__':
    if sys.argv[1:] == ['guardian']:
        ops.guardian()
    elif sys.argv[1:] == ['operation']:
        ops.run(config, ['init-fixture'], data=b'ab' * 32 + b'\n', readonly=False)
    else:
        raise SystemExit('Unexpected synthetic operation')
