"""Closed public launch contracts, distinct from actual private admission."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path('/opt/zunder-hosted-ordinary')
SOURCE = ROOT / 'source'
CHECKOUT = ROOT / 'checkout'
WEBSITE = ROOT / 'runtime/website/source'
PUBLIC = Path('/run/zunder-hosted-ordinary')
CALLER = '.github/workflows/hosted-testnet-journey.yml'
WORKFLOW = '.github/workflows/hosted-testnet-journey-run.yml'
NEGATIVE = '.github/workflows/hosted-testnet-journey-negative.yml'
REPOSITORY = 'zunderlabs/zunder-guard'
ENVIRONMENT = 'release-testnet-journey'
TOOLS = {'python', 'node', 'systemd_run', 'systemctl', 'bash', 'gh', 'cosign',
         'slsa-verifier', 'jq', 'sha256sum', 'awk', 'cat', 'mkdir', 'ip', 'nft',
         'sysctl', 'openssl', 'certutil', 'bwrap', 'chromium'}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def decode(raw, maximum=4194304):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'Bounded public JSON required')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'Repeated public field refused')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'Nonfinite public value refused'))


def sha(value, length=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value),
         'Exact immutable digest required')
    return value


def relative(value):
    need(type(value) is str and 0 < len(value) <= 1024 and
         re.fullmatch(r'[A-Za-z0-9_./+@$\[\]-]+', value) and
         not value.startswith('/') and all(p not in ('', '.', '..') for p in value.split('/')),
         'Safe complete source member required')
    return value


def candidate(value):
    need(type(value) is dict and set(value) == {'tag', 'source', 'manifest_sha256'} and
         type(value['tag']) is str and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', value['tag']),
         'Exact signed candidate reference required')
    sha(value['source'], 40); sha(value['manifest_sha256'])
    return value


def identity(value):
    need(type(value) is dict and set(value) == {'control_source', 'caller_source', 'run_id', 'attempt'} and
         type(value['run_id']) is int and value['run_id'] > 0 and
         type(value['attempt']) is int and 1 <= value['attempt'] <= 9,
         'Actual hosted run identity required; browser contract caps attempts at nine')
    sha(value['control_source'], 40); sha(value['caller_source'], 40)
    return value


def runtime(value):
    need(type(value) is dict and set(value) == {'schema', 'files', 'roots', 'tools'} and
         type(value['schema']) is int and value['schema'] == 1 and
         type(value['files']) is dict and 0 < len(value['files']) <= 20000 and
         type(value['roots']) is dict and set(value['roots']) == {'python', 'node', 'packages'} and
         type(value['tools']) is dict and set(value['tools']) == TOOLS,
         'Complete reviewed hosted runtime inventory required')
    for root in value['roots'].values():
        need(type(root) is str and Path(root).is_absolute() and '..' not in Path(root).parts,
             'Canonical runtime root required')
    for path, expected in value['files'].items():
        need(type(path) is str and Path(path).is_absolute() and '..' not in Path(path).parts,
             'Absolute runtime member required')
        sha(expected)
    for name, ref in value['tools'].items():
        need(type(ref) is dict and set(ref) == {'file', 'sha256'} and
             value['files'].get(ref['file']) == ref['sha256'], 'Tool outside reviewed runtime refused')
    need(value['tools']['systemd_run']['file'] == '/usr/bin/systemd-run' and
         value['tools']['systemctl']['file'] == '/usr/bin/systemctl', 'Fixed systemd tools required')
    return value
