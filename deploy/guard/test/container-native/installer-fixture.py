"""Synthetic setup process only: no HTTP/venue/order code; no real credentials."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

key = sys.stdin.buffer.readline(256).strip()
if key != b'ab' * 32:
    raise SystemExit('Synthetic input mismatch')
if sys.argv[1:] == ['init-fixture']:
    print('SYNTHETIC-PRIVATE-CLIENT-DO-NOT-LOG', flush=True)
Path('/data/operation-ready.json').write_text(json.dumps({'uid': os.getuid(), 'input_sha': hashlib.sha256(key).hexdigest()}))
while True:
    time.sleep(1)
